# File format is comma separated values, of which:
# 1st value is the user email address, to be used as username
# 2nd value is a string containing the user name
# 3rd value is a semicolon separated list of key=value pairs. Possible values are documented in https://mailman.readthedocs.io/en/latest/src/mailman/rest/docs/preferences.html
# 4th value is a semicolon separated list of additional email addresses to be associated to the username
# Ex:
# john@example.com,John Doe,delivery_status=by_user;receive_list_copy=False,john.doe@example.com;jdoe@someother.com
