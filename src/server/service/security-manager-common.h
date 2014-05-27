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
 * @file        security-manager-common.h
 * @author      Jan Cybulski (j.cybulski@samsung.com)
 * @author      Jacek Bukarewicz (j.bukarewicz@samsung.com)
 * @version     1.0
 * @brief       This file is header for utility functions for serurity-manager
 *
 */
#ifndef _SECURITY_MANAGER_COMMON_H_
#define _SECURITY_MANAGER_COMMON_H_

#include <string>


namespace SecurityManager {

/**
 * This function generates label for application with package identifier
 * read from @ref appPkgId and assigns it to @ref label.
 * @param[in] appPkgId application's package identifier.
 * @param[out] label string into which application's label will be stored into.
 * @return true on success, false on error.
 */
bool generateAppLabel(const std::string& appPkgId, std::string& label);

/**
 * Install package-specific smack rules.
 *
 * Function creates smack rules using predefined template. Rules are applied
 * to the kernel and saved on persistent storage so they are loaded on system boot.
 *
 * @param[in] pkgId - package identifier
 * @return true on success, false on error
 */
bool installPackageSmackRules(const std::string& pkgId);

/**
 * Uninstall package-specific smack rules.
 *
 * Function loads package-specific smack rules, revokes them from the kernel
 * and removes from persistent storage.
 *
 * @param[in] pkgId - package identifier
 * @return true on success, false on error
 */
bool uninstallPackageSmackRules(const std::string& pkgId);


} // namespace SecurityManager

#endif
