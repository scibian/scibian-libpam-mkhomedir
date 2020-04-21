# pam_mkhomedir.py: creates homedir of being logged in users and takes
# care of creating outer containers and setting up appropriate rights.
#
# Usage:
#   login session   requisite   pam_python.so pam_mkhomedir.py
#
# Dependencies:
# - libpam-python
# - acl

import pwd
import grp
import os
from os.path import exists
import sys
import syslog
import shutil

home_dir = "/home"
#scratch_dir = "/scratch"

debug_mode = False
skel_dir = '/etc/skel'

def debug(fmt, *args):
  if debug_mode:
    syslog.syslog(fmt % args)

def create_user_dir(pamh, basedir, user):
  userdir = os.path.join(basedir, user)

  if exists(userdir):
    if not os.path.isdir(userdir):
      debug ("-> unlink %s" % userdir)
      os.unlink(userdir)
      debug ("<- unlink %s" % userdir)

  if not exists(userdir):
    # Create user tree by copying content of /etc/skel
    debug ("-> shutil.copytree %s" % userdir)
    shutil.copytree(skel_dir + "/.", userdir, True)
    debug ("<- shutil.copytree %s" % userdir)
    # Userdir
    debug ("-> userdir chmod %s" % userdir)

    gid = pwd.getpwnam(user).pw_gid
    uid = pwd.getpwnam(user).pw_uid
    for root, dirs, files in os.walk(userdir):
        for f in files:
            os.chown(os.path.join(root,f), uid, gid)
            os.chmod(os.path.join(root,f), 0600)
    os.chown(userdir, uid, gid)
    os.chmod(userdir, 0700)
    debug ("<- userdir chmod %s" % userdir)

def pam_sm_authenticate(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_setcred(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_acct_mgmt(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_open_session(pamh, flags, argv):
  global debug_mode, skel_dir

  syslog.openlog("pam_mkhomedir", syslog.LOG_PID, syslog.LOG_AUTH)
  try:
    user = pamh.get_user(None)
  except pamh.exception, e:
    return e.pam_result

  if "debug" in argv:
    debug_mode = True

  skel_dirs = [ d.replace("skel=", "") for d in argv if d.startswith("skel=") ]
  if skel_dirs:
    skel_dir = skel_dirs[0]

  # Ignore users with uid < 1000
  minimum_uid = 1000
  if pwd.getpwnam(user).pw_uid < minimum_uid:
    return pamh.PAM_SUCCESS

  try:
    create_user_dir(pamh, home_dir, user)

    if exists("/local01/home"):
      create_user_dir(pamh, "/local01/home", user)

    return pamh.PAM_SUCCESS

  except Exception as inst:
    syslog.syslog(inst.__str__())
    return pamh.PAM_AUTH_ERR

def pam_sm_close_session(pamh, flags, argv):
  return pamh.PAM_SUCCESS

def pam_sm_chauthtok(pamh, flags, argv):
  return pamh.PAM_SUCCESS
