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
 * @file        smack-rules.cpp
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @version     1.0
 * @brief       Implementation of a class managing smack rules
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <fstream>

#include <dpl/log/log.h>

#include "smack-rules.h"
#include "security-manager-common.h"

namespace SecurityManager {

const char *const SMACK_APP_LABEL_TEMPLATE     = "~APP~";

SmackRules::SmackRules()
{
    if (smack_accesses_new(&m_handle) < 0) {
        LogError("Failed to create smack_accesses handle");
        throw std::bad_alloc();
    }
}

SmackRules::~SmackRules() {
    smack_accesses_free(m_handle);
}

bool SmackRules::add(const std::string &subject, const std::string &object,
        const std::string &permissions)
{
    return 0 == smack_accesses_add(m_handle, subject.c_str(), object.c_str(), permissions.c_str());
}

bool SmackRules::clear() const
{
    return 0 == smack_accesses_clear(m_handle);
}

bool SmackRules::apply() const
{
    return 0 == smack_accesses_apply(m_handle);
}

bool SmackRules::loadFromFile(const std::string &path)
{
    int fd;
    bool ret = true;

    fd = open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        LogError("Failed to open file: %s" << path);
        return false;
    }

    if (smack_accesses_add_from_file(m_handle, fd)) {
        LogError("Failed to load smack rules from file: %s" << path);
        ret = false;
    }

    close(fd);
    return ret;
}

bool SmackRules::saveToFile(const std::string &path) const
{
    int fd;
    bool ret = true;

    fd = open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644);
    if (fd == -1) {
        LogError("Failed to create file: %s" << path);
        return false;
    }

    if (smack_accesses_save(m_handle, fd)) {
        LogError("Failed to save rules to file: %s" << path);
        unlink(path.c_str());
        ret = false;
    }

    close(fd);
    return ret;
}


bool SmackRules::addFromTemplateFile(const std::string &path, const std::string &pkgId)
{
    std::vector<std::string> templateRules;
    std::string line;
    std::ifstream templateRulesFile(path);

    if (!templateRulesFile.is_open()) {
        LogError("Cannot open rules template file: " << path);
        return false;
    }

    while (std::getline(templateRulesFile, line)) {
        templateRules.push_back(line);
    }

    if (templateRulesFile.bad()) {
        LogError("Error reading template file: " << path);
        return false;
    }

    return addFromTemplate(templateRules, pkgId);
}

bool SmackRules::addFromTemplate(const std::vector<std::string> &templateRules,
        const std::string &pkgId)
{
    std::string tokens[3];
    std::string &subject = tokens[0];
    std::string &object = tokens[1];
    std::string &permissions = tokens[2];

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
            if (!SecurityManager::generateAppLabel(pkgId, subject)) {
                LogError("Failed to generate app label from pkgid: " << pkgId);
                return false;
            }
        }

        if (objectIsTemplate) {
            if (!SecurityManager::generateAppLabel(pkgId, object)) {
                LogError("Failed to generate app label from pkgid: " << pkgId);
                return false;
            }
        }

        if (!add(subject, object, permissions)) {
            LogError("Failed to add rule: " << subject << " " << object << " " << permissions);
            return false;
        }
    }

    return true;
}


bool SmackRules::tokenizeRule(const std::string &rule, std::string tokens[], int size)
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

} // namespace SecurityManager

