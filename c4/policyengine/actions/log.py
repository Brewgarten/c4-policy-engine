"""
Copyright (c) IBM 2015-2017. All Rights Reserved.
Project name: c4-policy-engine
This project is licensed under the MIT License, see LICENSE

Logging actions
"""
import logging

from c4.policyengine import Action

logging.basicConfig(format='%(asctime)s [%(levelname)s] <%(processName)s> [%(filename)s:%(lineno)d] - %(message)s', level=logging.INFO)

class Log(Action):
    """
    Basic logging action
    """
    id = "System.log"

    def perform(self, string):
        logging.error("'%s' '%s'", self.id, string)
        return True
