#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 EDF SA
#
# This file is part of libpam-mkhomedir-scibian.
#
# libpam-mkhomedir-scibian is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# libpam-mkhomedir-scibian is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with slurm-web.  If not, see <http://www.gnu.org/licenses/>.
#
# pam_mkhomedir.py: creates homedir of being logged in users and takes
# care of creating outer containers and setting up appropriate rights.
#
# Usage:
#   login session   requisite   pam_python.so pam_mkhomedir.py

import ConfigParser
import pwd
import os
from os.path import exists
import shutil
import syslog

# Read configuration from /etc/pam_mkhomedir.ini
config = ConfigParser.ConfigParser()
config.read("/etc/pam_mkhomedir.ini")

home_dir = config.get("config", "home_dir")
scratch_dir = config.get("config", "scratch_dir")
skel_dir = config.get("config", "skel_dir")
debug_level = config.get("config", "debug_level")
acl = config.getboolean("config", "acl")

syslog.openlog("pam_mkhomedir", syslog.LOG_PID, syslog.LOG_AUTH)

if debug_level == "error":
    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_ERR))
elif debug_level == "debug":
    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_DEBUG))
else:  # info or something wrong
    syslog.setlogmask(syslog.LOG_UPTO(syslog.LOG_INFO))


def debug(msg):
    syslog.syslog(syslog.LOG_DEBUG, msg)


def error(msg):
    syslog.syslog(syslog.LOG_ERR, msg)


def info(msg):
    syslog.syslog(syslog.LOG_INFO, msg)


def create_user_dir(pamh, basedir, user, skel=False):
    # Some user might have a personal directory that has not the same
    # name as their username, we use the last directory of the
    # homedir entry ('/home/toto' -> 'toto')
    userdir_basename = os.path.basename(pwd.getpwnam(user).pw_dir)
    userdir = os.path.join(basedir, userdir_basename)
    uid = pwd.getpwnam(user).pw_uid
    maingid = pwd.getpwnam(user).pw_gid

    if exists(userdir):
        if not os.path.isdir(userdir):
            info("%s is not a dir, fixing it" % (userdir))
            debug("-> unlink %s" % userdir)
            os.unlink(userdir)
            debug("<- unlink %s" % userdir)
        elif acl:
            if os.system("setfacl -m u:%s:rwx %s" % (user, userdir)) != 0:
                error("Setting ACLs for user %s on %s failed!" % (user, userdir))

    if not exists(userdir):
        info("Creating %s" % basedir)
        if skel:
            # Create user tree by copying content of /etc/skel
            debug("-> shutil.copytree %s" % userdir)
            shutil.copytree(skel_dir + "/.", userdir, True)
            debug("<- shutil.copytree %s" % userdir)
        else:
            debug("-> mkdir %s" % userdir)
            os.mkdir(userdir)
            debug("<- mkdir %s" % userdir)

        debug("-> recursive chown %s" % userdir)
        for root, dirs, files in os.walk(userdir):
            for d in dirs:
                os.chown(os.path.join(root, d), uid, maingid)
            for f in files:
                os.chown(os.path.join(root, f), uid, maingid)
        debug("<- recursive chown %s" % userdir)

    if acl:
        # Userdir
        debug("-> userdir chmod %s" % userdir)
        os.chown(userdir, 0, 0)
        os.chmod(userdir, 0700)
        debug("<- userdir chmod %s" % userdir)
        # Set ACL on user's dir
        info("Setting up ACL for %s" % userdir)
        if os.system("setfacl -m u:%s:rwx %s" % (user, userdir)) != 0:
            error("Setting ACLs for user %s on %s failed!" % (user, userdir))
    else:
        # give new dir to user (recursive chown does not include the userdir)
        os.chown(userdir, uid, maingid)


def pam_sm_authenticate(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_setcred(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_acct_mgmt(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_open_session(pamh, flags, argv):

    try:
        user = pamh.get_user(None)
    except pamh.exception, e:
        return e.pam_result

    if skel_dir is "":
       skel = False
    else:
       skel = True

    # Ignore users with uid < 1000
    minimum_uid = 1000
    if pwd.getpwnam(user).pw_uid < minimum_uid:
        return pamh.PAM_SUCCESS

    try:
        if home_dir is not "":
            create_user_dir(pamh, home_dir, user, skel)

        if scratch_dir is not "":
            create_user_dir(pamh, scratch_dir, user, False)
            pamh.env['SCRATCHDIR'] = os.path.join(scratch_dir, user)

        return pamh.PAM_SUCCESS

    except Exception as inst:
        error(inst.__str__())
        return pamh.PAM_AUTH_ERR


def pam_sm_close_session(pamh, flags, argv):
    return pamh.PAM_SUCCESS


def pam_sm_chauthtok(pamh, flags, argv):
    return pamh.PAM_SUCCESS
