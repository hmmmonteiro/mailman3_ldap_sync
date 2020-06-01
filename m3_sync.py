#!/usr/bin/env python
#
# Forked from Imam Omar Mochtar's m3_sync.py

__author__ = ('Hugo Monteiro')
__email__ = ('monteiro.hugo@gmail.com',)
__version__ = "1.2"
__license__ = "GPL"

import os
import sys
import re
import logging
import traceback
import csv
import time
import random
import string
from pprint import pprint
from mailmanclient import Client as Mailman3Client
from colorlog import ColoredFormatter
from six.moves.urllib_error import HTTPError
from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, BASE
try:
    from ConfigParser import ConfigParser
except ImportError:
    # for python 3
    from configparser import ConfigParser


class M3Sync(object):

    __attrs = ['subscriber', 'owner', 'moderator']
    __default_settings = ['send_welcome_message', 'max_message_size']
    logger = logging.getLogger('Mailman3Sync')

    def __init__(self, config):

        self.sync = dict(config.items('sync'))
        self.config = config

        self.init_logger()
        self.init_hooks()
        self.init_mailman3api()
        self.init_ldap()

    def init_hooks(self):
        """
        Initialize hooks, for any module that will be executed after sync was done
        """
        conf = dict(self.config.items('hooks'))
        self.hooks = []
        for hook, module_name in conf.items():
            self.hooks.append({
                'name': hook,
                'module': getattr(__import__("hooks.{0}".format(module_name)), module_name),
                'conf': {} if not self.config.has_section(hook) else dict(self.config.items(hook))
            })

    def init_ldap(self):
        """
        Initialize ldap connection
        """
        conf = dict(self.config.items('ldap'))
        self.ldap = Connection(
            Server(conf['host'], get_info=ALL),
            conf['bind_dn'], conf['bind_pwd'], auto_bind=True
        )

    def init_mailman3api(self):
        """
        Initialize mailman3 API
        """
        # set conf api
        conf = dict(self.config.items('mailman3'))
        self.m3 = Mailman3Client(
            'http://{0}:{1}/3.1'.format(conf['host'], conf['port']),
            conf['user'], conf['pwd']
        )
        try:
            self.m3.system
        except Exception:
            msg = traceback.format_exc(limit=1)
            self.logger.error(
                "Error while connecting to conf api: {0}".format(msg))

    def set_preferences(self, src_prefs, tgt_prefs):
        """Sets preferences on user."""
        tgt_pref = None
        for src_pref in src_prefs:
            tgt_prefs[src_pref] = str(src_prefs[src_pref])
        try:
            tgt_prefs.save()
        except Exception:
            msg = traceback.format_exc(limit=1)
            self.logger.error(
                "Error while seeting preferences: {0}".format(msg))
    #end set_preferences

    def init_logger(self):
        """
        Initiate log console & file (if enabled)
        """
        formatter = ColoredFormatter(
            "%(yellow)s%(asctime)s %(reset)s- %(log_color)s%(levelname)-8s%(reset)s - %(blue)s%(message)s",
            reset=True,
            log_colors={
                'DEBUG': 'cyan',
                'INFO':	 'green',
                'WARNING': 'yellow',
                'ERROR': 'red',
                'CRITICAL': 'blue',
            }
        )

        log_lvl = self.sync['log_level']

        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

        self.logger.addHandler(handler)
        self.logger.setLevel(log_lvl)

        if 'log_file' in self.sync and self.sync['log_file']:
            try:
                fh = logging.FileHandler(self.sync['log_file'], 'a')
                fh.setLevel(log_lvl)
                fh.setFormatter(
                    logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
                )
                self.logger.addHandler(fh)
            except OSError:
                print('There was a problem opening file {0} for writting. Check file and path permissions and ownerships.'.format(self.sync['log_file']))
                sys.exit()

    def get_list_byname(self, domain, list_name):
        """
        a wrapper for get list by name
        """
        for mlist in domain.lists:
            if mlist.list_name != list_name:
                continue
            return mlist
        return None

    def get_list(self, name):
        """
        get list with additional prefix if enabled
        """
        prefix = self.sync['list_prefix']
        # lowercased
        name = name.lower()
        if not prefix:
            return name
        return "{0}{1}".format(prefix, name)

    def exec_hooks(self, ldap_data):
        """
        Running all available hooks
        """
        for hook in self.hooks:
            name = hook['name']
            self.logger.info("Executing hook {0}".format(name))
            result = hook['module'].main(
                conf=hook['conf'],
                instance=self,
                data=ldap_data
            )
            if result:
                self.logger.info(
                    "Result of hoook {0} is {1}".format(name, result))

    def set_ldap_attrs(self):
        return list(filter(None, [ x if '{0}_attr'.format(x) in self.sync else None for x in self.__attrs]))

    def set_default_settings(self, mlist):
        for setting in self.__default_settings:
            mlist.settings[setting] = self.sync['set_{0}'.format(setting)]
        mlist.settings.save()

    def str_to_bool(self, string):
        if string == 'True':
            return True
        elif string == 'False':
            return False
        else:
             raise ValueError # evil ValueError that doesn't tell you what the wrong value was

    def main(self):
        __ldap_attrs = self.set_ldap_attrs()
        ret_attr = list([self.sync['group_name_attr']])
        for ldap_attr in __ldap_attrs:
            ret_attr.append(self.sync['{0}_attr'.format(ldap_attr)])
        search_result = self.ldap.search(
            self.sync['search_base'],
            self.sync['group_filter'],
            attributes=ret_attr
        )

        # regex was taken from http://emailregex.com/
        email_re = re.compile(
            r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")

        ldap_data = {}
        for group in self.ldap.entries:
            # change all space to dot for group name
            list_name = re.sub(
                r'\s+', '.', getattr(group, self.sync['group_name_attr']).value)

            #
            ldap_data[self.get_list(list_name)] = dict(
                zip(__ldap_attrs, [[] for x in range(len(__ldap_attrs))])
            )

            for attr in __ldap_attrs:
                for dn in getattr(group, self.sync['{0}_attr'.format(attr)]):
                    # if it's not email form then search by it's DN. this is used if quering group member agains AD
                    email = None
                    if email_re.search(dn):
                        email = dn
                    else:
                        user_attrs = []
                        for user_attr in [self.sync['mail_attr'], self.sync['name_attr'], self.sync['mailalias_attr'], self.sync['mluserprefs_attr']]:
                            if user_attr is not '':
                                user_attrs.append(user_attr)
                        self.ldap.search(
                            dn,
                            self.sync['member_filter'],
                            attributes=user_attrs,
                            search_scope=BASE
                        )

                        email = getattr(
                            self.ldap.entries[0], self.sync['mail_attr']).value.lower()
                        if 'replace_mail_domain' in self.sync and self.sync['replace_mail_domain']:
                            email = re.sub(r'@.*?$', '@{}'.format(self.sync['replace_mail_domain']), email)
                        user_entry = {}
                        user_entry[email] = {}

                        if self.sync['name_attr']:
                            display_name = getattr(
                                self.ldap.entries[0], self.sync['name_attr']).value
                            user_entry[email]['display_name'] = display_name

                        if self.sync['mailalias_attr']:
                            email_alias = getattr(
                                self.ldap.entries[0], self.sync['mailalias_attr']).value
                            if not isinstance(email_alias, str):
                                email_alias = str(';'.join(email_alias))
                            user_entry[email]['email_alias'] = email_alias

                        if self.sync['mluserprefs_attr']:
                            mlist_user_prefs = getattr(
                                self.ldap.entries[0], self.sync['mluserprefs_attr']).value
                            if not isinstance(mlist_user_prefs, str):
                                mlist_user_prefs = str(';'.join(mlist_user_prefs))
                            user_entry[email]['mlist_user_prefs'] = mlist_user_prefs

                    if not email:
                        self.logger.warning('LDAP data for {}, is not an email or it doesn\'t has email attribute'.format(dn))
                        continue

                    ldap_data[self.get_list(list_name)][attr] = dict(ldap_data[self.get_list(list_name)][attr], **user_entry)

        # make sure default domain exist
        if self.sync['default_list_domain'] not in str(self.m3.domains):
            try:
                self.logger.info('Creating default list domain: {0}'.format(
                    self.sync['default_list_domain']))
                self.m3.create_domain(self.sync['default_list_domain'])
            except HTTPError:
                self.logger.warning('Error while creating domain {0}'.format(
                    self.sync['default_list_domain']))
        else:
            self.logger.debug('domain {0} already exist. Skipping.'.format(
                self.sync['default_list_domain']))

        domain = self.m3.get_domain(self.sync['default_list_domain'])

        # LDAP -> MAILMAN add data to mailman
        for list_name, datas in ldap_data.items():
            if list_name not in str(self.m3.get_lists(advertised=True)):
                # Create List
                self.logger.info("Create list {0} in domain {1}".format(
                    list_name, self.sync['default_list_domain']))
                try:
                    mlist = domain.create_list(list_name)
                    # set list default settings
                    self.set_default_settings(mlist)
                except HTTPError:
                    self.logger.warning(
                        "Error while creating List {0}".format(list_name))
                    mlist = self.get_list_byname(domain, list_name)
            else:
                self.logger.info(
                    "List with name {0} already exists".format(list_name))

            mlist = self.get_list_byname(domain, list_name)

            mlist_name = mlist.fqdn_listname

            # subscriber
            if self.sync['load_csv_path']:
                try:
                    with open('{0}/{1}.csv'.format(self.sync['load_csv_path'],mlist_name), mode='r') as infile:
                        reader = csv.reader(filter(lambda row: row[0]!='#', infile), skipinitialspace=True)
                        extra_members = {}
                        for row in reader:
                            extra_members[row[0]] = {}
                            extra_members[row[0]]['display_name'] = row[1]
                            extra_members[row[0]]['mlist_user_prefs'] = row[2]
                            extra_members[row[0]]['email_alias'] = row[3]
                        infile.close()
                        datas['subscriber'] = dict(datas['subscriber'], **extra_members)
                except OSError:
                    continue

            for subscriber in datas['subscriber'].keys():
                sync_userdata = self.str_to_bool(self.sync['sync_userdata'])
                subscriber_email = subscriber

                try:
                    user = self.m3.get_user(subscriber)

                except HTTPError:
                    self.logger.info("User {0} doesn't exist. Creating.".format(subscriber))
                    try:
                        password = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
                        user = self.m3.create_user(subscriber, password)
                        user.add_address(subscriber,absorb_existing=True)

                        if 'email_alias' in datas['subscriber'][subscriber].keys():
                            if datas['subscriber'][subscriber]['email_alias'] is not '':
                                for email_alias in datas['subscriber'][subscriber]['email_alias'].split(";"):
                                    self.logger.info('    Adding address {0} to user {1}'.format(
                                        email_alias, subscriber))
                                    user.add_address(email_alias,absorb_existing=False)

                    except HTTPError:
                        self.logger.warning("There was an error while creating user {0}".format(
                            subscriber))
                        sync_userdata = False

                if sync_userdata:
                    if 'display_name' in datas['subscriber'][subscriber].keys():
                        if datas['subscriber'][subscriber]['display_name'] is '':
                            datas['subscriber'][subscriber]['display_name'] = None
                        self.logger.info('    Syncing display_name of {0} to LDAP value {1}'.format(subscriber, datas['subscriber'][subscriber]['display_name']))
                        user.display_name = str(datas['subscriber'][subscriber]['display_name'])
                        
                user.save()

                if not mlist.is_member(subscriber):
                    sync_userdata = True
                    try:
                        self.logger.info("Add subscriber {0} to list {1}.".format(
                            subscriber_email, mlist_name))
                        mlist.subscribe(subscriber_email, pre_verified=True, pre_confirmed=True, pre_approved=True)

                    except HTTPError:
                        self.logger.warning("There was an error while subscribing {0} to {1}".format(
                            subscriber_email, mlist_name))
                        sync_userdata = False
                else:
                     self.logger.info("subscriber {0} already exist in {1}".format(
                         subscriber_email, mlist_name))

                if sync_userdata:
                    if 'mlist_user_prefs' in datas['subscriber'][subscriber].keys():
                        if datas['subscriber'][subscriber]['mlist_user_prefs'].find('=') is not -1:
                            self.logger.info("    Setting member {0} prefs on list {1}.".format(
                                subscriber_email, mlist_name))
                            prefs = dict(x.split("=") for x in datas['subscriber'][subscriber]['mlist_user_prefs'].split(";"))
                            self.set_preferences(prefs, mlist.get_member(subscriber).preferences)


            # moderator
            if 'moderator' not in datas.keys():
                datas['moderator'] = {}

            if 'set_moderator' in self.sync and self.sync['set_moderator']:
                for x in self.sync['set_moderator'].split(";"):
                    datas['moderator'][x] = True
                    
            for moderator in datas['moderator'].keys():
                if not mlist.is_moderator(moderator):
                    try:
                        self.logger.info(
                            "Add moderator {0} to list {1}".format(moderator, mlist_name))
                        mlist.add_moderator(moderator)
                    except HTTPError:
                        self.logger.warning(
                            "There was an error while setting {0} has moderator in {1}".format(moderator, mlist_name))
                else:
                    self.logger.info("moderator {0} already exist in {1}".format(
                        moderator, mlist_name))

            # owner
            if 'owner' not in datas.keys():
                datas['owner'] = {}
           
            if 'set_owner' in self.sync and self.sync['set_owner']:
                for x in self.sync['set_owner'].split(";"):
                    datas['owner'][x] = True
                    
            for owner in datas['owner'].keys():
                if not mlist.is_owner(owner):
                    try:
                        self.logger.info(
                            "Add owner {0} to list {1}".format(owner, mlist_name))
                        mlist.add_owner(owner)
                    except HTTPError:
                        self.logger.warning(
                            "There was an error while setting {0} has owner in {1}".format(owner, mlist_name))
                else:
                    self.logger.info("owner {0} already exist in {1}".format(
                        owner, mlist_name))


        # MAILMAN -> LDAP, check for diff then remove when it not exist
        # comparing member, if doesn't exist in ldap data then delete them
        for mlist in domain.lists:
            list_name = mlist.list_name
            # delete the rest of list if doesn't exist in ldap
            if list_name not in ldap_data.keys():

                if self.sync['delete_rest_list'] == 'true':

                    # some are excluded using regex pattern
                    if self.sync['exclude_list_re'] and re.search(r'{0}'.format(self.sync['exclude_list_re']), mlist.list_name):
                        continue

                    self.logger.info(
                        "Deleting list {0}".format(mlist.fqdn_listname))
                    mlist.delete()

                continue

            for member in mlist.members:
                ldapset = ldap_data[list_name]['subscriber'].keys()
                if member.email not in ldapset:
                    self.logger.info("Unsubscribe {0} from list {1}".format(
                        member.email, list_name))
                    member.unsubscribe()

            for moderator in mlist.moderators:
                ldapset = ldap_data[list_name]['moderator'].keys()
                if moderator.email not in ldapset:
                    self.logger.info(
                        "Removing moderator {0} from list {1}".format(moderator.email, list_name))
                    mlist.remove_moderator(moderator.email)

            for owner in mlist.owners:
                ldapset = ldap_data[list_name]['owner'].keys()
                if owner.email not in ldapset:
                    self.logger.info(
                        "Removing owner {0} from list {1}".format(owner.email, list_name))
                    mlist.remove_owner(owner.email)

        self.exec_hooks(ldap_data)


if __name__ == "__main__":

    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    MAIN_CONF = os.path.join(BASE_DIR, 'config.ini')

    if not os.path.isfile(MAIN_CONF):
        logExit("main configuration not found")

    parser = ConfigParser()
    parser.read(MAIN_CONF)

    M3Sync(
        config=parser
    ).main()
