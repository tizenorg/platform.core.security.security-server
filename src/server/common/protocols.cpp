/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
/*
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by security server.
 */

#include <protocols.h>
#include <cstddef>


namespace SecurityServer {

#define SOCKET_PATH_PREFIX "/run/"
#define SOCKET_PATH_PREFIX_SECURITY_SERVER SOCKET_PATH_PREFIX "security-server/"

char const * const SERVICE_SOCKET_SHARED_MEMORY =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-data-share.socket";
char const * const SERVICE_SOCKET_GET_GID =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-get-gid.socket";
char const * const SERVICE_SOCKET_PRIVILEGE_BY_PID =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-privilege-by-pid.socket";
char const * const SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-app-privilege-by-name.socket";
char const * const SERVICE_SOCKET_COOKIE_GET =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-cookie-get.socket";
char const * const SERVICE_SOCKET_COOKIE_CHECK =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-cookie-check.socket";
char const * const SERVICE_SOCKET_PASSWD_CHECK =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-password-check.socket";
char const * const SERVICE_SOCKET_PASSWD_SET =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-password-set.socket";
char const * const SERVICE_SOCKET_PASSWD_RESET =
        SOCKET_PATH_PREFIX_SECURITY_SERVER "security-server-api-password-reset.socket";

const size_t COOKIE_SIZE = 20;

const size_t MAX_PASSWORD_LEN = 32;
const unsigned int MAX_PASSWORD_HISTORY = 50;
const unsigned int PASSWORD_INFINITE_EXPIRATION_DAYS = 0;
const unsigned int PASSWORD_INFINITE_ATTEMPT_COUNT = 0;
const unsigned int PASSWORD_API_NO_EXPIRATION = 0xFFFFFFFF;

const int SECURITY_SERVER_MAX_OBJ_NAME = 30;

} // namespace SecurityServer

