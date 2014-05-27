/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/**
 * @file        security-manager-common.cpp
 * @author      Jan Cybulski (j.cybulski@samsung.com)
 * @author      Jacek Bukarewicz (j.bukarewicz@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of utility functions for serurity-manager
 *
 */

#include <vector>
#include <fstream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/smack.h>
#include <linux/limits.h>

#include <dpl/log/log.h>

#include "security-manager-common.h"

namespace SecurityManager {
namespace {

const char* const APP_RULES_TEMPLATE_FILE_PATH = "/etc/smack/app-rules-template.smack";
const char* const APP_RULES_PATH_FORMAT        = "/etc/smack/accesses.d/%s";
const char* const SMACK_APP_LABEL_TEMPLATE     = "~APP~";

bool tokenizeRule(const std::string& rule, std::string tokens[], int size)
{
    size_t startPos;
    size_t endPos = 0;
    const char delimiters[] = " \t\n\r";

    for (int i = 0; i < size; i++) {
        startPos = rule.find_first_not_of(delimiters, endPos);
        if (startPos == std::string::npos) {
            LogError("Unexpected end of rule: " << rule);
            return false;
        }

        endPos = rule.find_first_of(delimiters, startPos);
        tokens[i] = rule.substr(startPos, endPos - startPos);
    }

    if (endPos != std::string::npos &&
        rule.find_first_not_of(delimiters, endPos) != std::string::npos) {
        LogError("Too many tokens found in rule: " << rule);
        return false;
    }

    return true;
}

bool generateRulesFromTemplate(smack_accesses* handle, const std::vector<std::string>& templateRules,
        const std::string& pkgId)
{
    std::string tokens[3];
    std::string& subject = tokens[0];
    std::string& object = tokens[1];
    std::string& permissions = tokens[2];

    for (auto rule = templateRules.begin(); rule != templateRules.end(); ++rule) {
        if (rule->length() == 0)
            continue;

        if (!tokenizeRule(*rule, tokens, sizeof(tokens) / sizeof(*tokens))) {
            return false;
        }

        bool subjectIsTemplate = (subject == SMACK_APP_LABEL_TEMPLATE);
        bool objectIsTemplate = (object == SMACK_APP_LABEL_TEMPLATE);

        if (objectIsTemplate == subjectIsTemplate) {
            LogError("Invalid rule template. Exactly one app label template expected: " << *rule);
            return false;
        }

        if (subjectIsTemplate) {
            if (!generateAppLabel(pkgId, subject)) {
                LogError("Failed to generate app label from pkgid: " << pkgId);
                return false;
            }
        }

        if (objectIsTemplate) {
            if (!generateAppLabel(pkgId, object)) {
                LogError("Failed to generate app label from pkgid: " << pkgId);
                return false;
            }
        }

        if (smack_accesses_add(handle, subject.c_str(), object.c_str(), permissions.c_str())) {
            LogError("smack_accesses_add failed on rule: " << subject << " " << object << " " << permissions);
            return false;
        }
    }

    return true;
}

bool loadRulesForInstalledApp(smack_accesses* handle, const std::string& pkgId)
{
    char path[PATH_MAX];
    int fd;
    bool ret = true;

    snprintf(path, sizeof(path), APP_RULES_PATH_FORMAT, pkgId.c_str());
    fd = open(path, O_RDONLY);
    if (fd == -1) {
        LogError("Failed to open file: %s" << path);
        return false;
    }

    if (smack_accesses_add_from_file(handle, fd)) {
        LogError("Failed to load smack rules from file: %s" << path);
        ret = false;
    }

    close(fd);
    return ret;
}

bool saveRulesToFile(smack_accesses* handle, const std::string& pkgId)
{
    char path[PATH_MAX];
    int fd;
    bool ret = true;

    snprintf(path, sizeof(path), APP_RULES_PATH_FORMAT, pkgId.c_str());
    fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        LogError("Failed to create file: %s" << path);
        return false;
    }

    if (smack_accesses_save(handle, fd)) {
        LogError("Failed to save rules to file: %s" << path);
        unlink(path);
        ret = false;
    }

    close(fd);
    return ret;
}
} // namespace

bool generateAppLabel(const std::string& appPkgId, std::string& label)
{
    (void) appPkgId; //todo use pkgId to generate label
    label = "User";
    return true;
}

bool installPackageSmackRules(const std::string& pkgId) {
    std::string line;
    std::vector<std::string> rules_vector;
    smack_accesses* handle = NULL;
    bool ret = true;
    std::ifstream ruleTemplateFile(APP_RULES_TEMPLATE_FILE_PATH);

    if (!ruleTemplateFile.is_open()) {
        LogError("Cannot open file: " << APP_RULES_TEMPLATE_FILE_PATH);
        return false;
    }

    while (getline(ruleTemplateFile, line)) {
        rules_vector.push_back(line);
    }

    if (ruleTemplateFile.bad()) {
        LogError("Error reading template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        return false;
    }

    if (smack_accesses_new(&handle)) {
        LogError("Failed to create smack_accesses handle");
        return false;
    }

    if (!generateRulesFromTemplate(handle, rules_vector, pkgId)) {
        ret = false;
        goto out;
    }

    if (smack_accesses_apply(handle)) {
        LogError("Failed to apply application rules to kernel");
        ret = false;
        goto out;
    }

    if (!saveRulesToFile(handle, pkgId)) {
        smack_accesses_clear(handle);
        ret = false;
        goto out;
    }

out:
    smack_accesses_free(handle);
    return ret;
}

bool uninstallPackageSmackRules(const std::string& pkgId)
{
    char path[PATH_MAX];
    bool ret = true;
    smack_accesses* handle;

    if (smack_accesses_new(&handle)) {
        LogError("Failed to create smack_accesses handle");
        return false;
    }

    if (!loadRulesForInstalledApp(handle, pkgId)) {
        ret = false;
        goto out;
    }

    snprintf(path, sizeof(path), APP_RULES_PATH_FORMAT, pkgId.c_str());
    if (unlink(path)) {
        LogError("Failed to remove smack rules file: " << path);
        ret = false;
        // carry on with uninstallation
    }

    if (smack_accesses_clear(handle)) {
        LogError("Failed to clear smack kernel rules for pkgId: " << pkgId);
        ret = false;
    }

out:
    smack_accesses_free(handle);
    return ret;
}

} // namespace SecurityManager

