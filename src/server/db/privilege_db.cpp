/*
 * security-manager, database access
 *
 * Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Krzysztof Sasiak <k.sasiak@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

/*
 * @file        PrivilegeDb.cpp
 * @author      Krzysztof Sasiak (k.sasiak@samsung.com)
 * @version     0.1
 * @brief       This file contains declaration of the API to privileges database.
 */

#include <cstdio>
#include <list>
#include <string>
#include <iostream>

#include <dpl/log/log.h>
#include "privilege_db.h"

#define STRINGIFY(x) x.c_str()
#define CATCH_STANDARD_EXCEPTIONS  \
    catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) { \
        LogDebug("Syntax error in command: " << e.DumpToString()); \
        ThrowMsg(SecurityServer::PrivilegeDb::Exception::InternalError, \
            "Syntax error in command: " << e.DumpToString()); \
    } catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) { \
        LogDebug("Mysterious internal error in SqlConnection class" << e.DumpToString()); \
        ThrowMsg(SecurityServer::PrivilegeDb::Exception::InternalError, \
            "Mysterious internal error in SqlConnection class: " << e.DumpToString()); \
    }

using namespace std;

namespace SecurityServer {

PrivilegeDb::PrivilegeDb(const std::string &path) {
    try {
        mSqlConnection = new SecurityServer::DB::SqlConnection(path,
                SecurityServer::DB::SqlConnection::Flag::None,
                SecurityServer::DB::SqlConnection::Flag::RW);
    } catch (SecurityServer::DB::SqlConnection::Exception::Base &e) {
        LogError("Database initialization error: " << e.DumpToString());
        ThrowMsg(SecurityServer::PrivilegeDb::Exception::IOError,
                "Database initialization error:" << e.DumpToString());

    };
}

PrivilegeDb::~PrivilegeDb() {
    delete mSqlConnection;
}
;

void PrivilegeDb::BeginTransaction(void) {
    mSqlConnection->BeginTransaction();
}

void PrivilegeDb::CommitTransaction(void) {
    mSqlConnection->CommitTransaction();
}

void PrivilegeDb::RollbackTransaction(void) {
    mSqlConnection->RollbackTransaction();
}

bool PrivilegeDb::PkgIdExists(const std::string &pkgId) {

    try {
        SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(TQueryType::EPkgIdExists));
        command->BindString(1, STRINGIFY(pkgId));
        if (command->Step()) {
            LogPedantic("PkgId: " << pkgId << " found in database");
            command->Reset();
            return true;
        };

    } CATCH_STANDARD_EXCEPTIONS;

    return false;
}

bool PrivilegeDb::PkgIdHasPermissions(const std::string &pkgId,
        const TPermissionsList &permissions, TPermissionsList &newPermissions) {

    try {
        SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(TQueryType::EPermissionForPkgIdExists));
        for (auto permission : permissions) {
            command->BindString(1, STRINGIFY(pkgId));
            command->BindString(2, permission);
            //remove element from original list if database found an entry
            if (command->Step()) {
                LogPedantic(
                        "PkgId: " << pkgId << " already has permission: " << permission <<" in database");
            } else {
                LogPedantic(
                        "PkgId: " << pkgId << " doesn't have permission: " << permission <<" in database");
                newPermissions.push_back(permission);
            };

            command->Reset();
        }
        return true;

    } CATCH_STANDARD_EXCEPTIONS;

    return false;
}

bool PrivilegeDb::AddPermissions(const std::string &appId,
        const std::string &pkgId, const TPermissionsList &permissions,
        TPermissionsList &newPermissions) {

    bool ret = this->PkgIdHasPermissions(pkgId, permissions, newPermissions);
    if (!ret)
        return false;

    try {
        SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(TQueryType::EAddAppPermissions));

        for (auto permission : permissions) {
            command->BindString(1, STRINGIFY(appId));
            command->BindString(2, STRINGIFY(pkgId));
            command->BindString(3, permission);

            if (command->Step()) {
                LogPedantic(
                        "Unexpected SQLITE_ROW answer to query: " << TQueryType::EAddAppPermissions);
            };

            command->Reset();
            LogPedantic(
                    "Added appId: " << appId << ", pkgId: " << pkgId << ", permission: " << permission);

        }
        return true;

    } CATCH_STANDARD_EXCEPTIONS;
    return false;

}

bool PrivilegeDb::RemovePermissions(const std::string &appId,
        const std::string &pkgId, const TPermissionsList &permissions) {

    try {
        for (auto permission : permissions) {
            SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
                    mSqlConnection->PrepareDataCommand(
                            Queries.at(TQueryType::ERemoveAppPermissions));
            command->BindString(1, STRINGIFY(appId));
            command->BindString(2, STRINGIFY(pkgId));
            command->BindString(3, permission);
            command->Step();
            LogPedantic(
                    "Removed appId: " << appId << ", pkgId: " << pkgId << ", permission: " << permission);
        }
        return true;

    } CATCH_STANDARD_EXCEPTIONS;

    return false;
}

}

//namespace SecurityServer
