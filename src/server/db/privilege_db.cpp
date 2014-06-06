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
 * @file        privilege_db.cpp
 * @author      Krzysztof Sasiak (k.sasiak@samsung.com)
 * @version     0.1
 * @brief       This file contains declaration of the API to privileges database.
 */

#include <cstdio>
#include <set>
#include <list>
#include <string>
#include <iostream>

#include <dpl/log/log.h>
#include "privilege_db.h"

using namespace std;

namespace SecurityServer {

PrivilegeDb::PrivilegeDb(const std::string &path) {
    try {
        mSqlConnection = new DB::SqlConnection(path,
                DB::SqlConnection::Flag::None,
                DB::SqlConnection::Flag::RW);
    } catch (DB::SqlConnection::Exception::Base &e) {
        LogError("Database initialization error: " << e.DumpToString());
        ThrowMsg(PrivilegeDb::Exception::IOError,
                "Database initialization error:" << e.DumpToString());

    };
}

PrivilegeDb::~PrivilegeDb() {
    delete mSqlConnection;
}
;

void PrivilegeDb::BeginTransaction(void) {
    try {
        mSqlConnection->BeginTransaction();
    }CATCH_STANDARD_EXCEPTIONS;
}

void PrivilegeDb::CommitTransaction(void) {
    try {
        mSqlConnection->CommitTransaction();
    }CATCH_STANDARD_EXCEPTIONS;
}

void PrivilegeDb::RollbackTransaction(void) {
    try {
        mSqlConnection->RollbackTransaction();
    }CATCH_STANDARD_EXCEPTIONS;
}

bool PrivilegeDb::PkgIdExists(const std::string &pkgId) {

    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EPkgIdExists));
        command->BindString(1, pkgId.c_str());
        if (command->Step()) {
            LogPedantic("PkgId: " << pkgId << " found in database");
            command->Reset();
            return true;
        };

    }CATCH_STANDARD_EXCEPTIONS;

    return false;
}

bool PrivilegeDb::AddApplication(const std::string &appId,
        const std::string &pkgId, bool &pkgIdIsNew) {

    pkgIdIsNew = !(this->PkgIdExists(pkgId));

    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EAddApplication));

        command->BindString(1, appId.c_str());
        command->BindString(2, pkgId.c_str());

        if (command->Step()) {
            LogPedantic(
                    "Unexpected SQLITE_ROW answer to query: " << QueryType::EAddApplication);
        };

        command->Reset();
        LogPedantic( "Added appId: " << appId << ", pkgId: " << pkgId);

        return true;

    }CATCH_STANDARD_EXCEPTIONS;
    return false;

}

bool PrivilegeDb::RemoveApplication(const std::string &appId,
        const std::string &pkgId, bool &pkgIdIsNoMore) {

    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::ERemoveApplication));

        command->BindString(1, appId.c_str());
        command->BindString(2, pkgId.c_str());

        if (command->Step()) {
            LogPedantic(
                    "Unexpected SQLITE_ROW answer to query: " << QueryType::ERemoveApplication);
        };

        command->Reset();
        LogPedantic( "Removed appId: " << appId << ", pkgId: " << pkgId);

        pkgIdIsNoMore = !(this->PkgIdExists(pkgId));

        return true;

    }CATCH_STANDARD_EXCEPTIONS;
    return false;

}

bool PrivilegeDb::GetAppPermissions(const std::string &appId,
        const std::string &pkgId, TPermissionsList &currentPermissions) {
    try {
        DB::SqlConnection::DataCommandAutoPtr command =
                mSqlConnection->PrepareDataCommand(
                        Queries.at(QueryType::EGetAppPermissions));
        command->BindString(1, appId.c_str());
        command->BindString(2, pkgId.c_str());

        while (command->Step()) {
            std::string permission = command->GetColumnString(0);
            LogPedantic ("Got permission: "<< permission);
            currentPermissions.push_back(permission.c_str());
        };

        return true;
    }CATCH_STANDARD_EXCEPTIONS;

    return false;

}

bool PrivilegeDb::UpdatePermissions(const std::string &appId,
        const std::string &pkgId, const TPermissionsList &permissions,
        TPermissionsList &addedPermissions,
        TPermissionsList &removedPermissions) {

    DB::SqlConnection::DataCommandAutoPtr command;

    TPermissionsList curPermissions = TPermissionsList();
    if (!this->GetAppPermissions(appId, pkgId, curPermissions))
        return false;

    try {
        //Data compilation
        std::set<const char *> permissionsSet = std::set<const char *>(
                permissions.begin(), permissions.end());
        std::set<const char *> curPermissionsSet = std::set<const char *>(
                curPermissions.begin(), curPermissions.end());

        TPermissionsList tmpPermissions = TPermissionsList (permissions);
        tmpPermissions.merge (curPermissions);
        tmpPermissions.unique ();

        for (auto permission : tmpPermissions) {
            if ((SET_CONTAINS(permissionsSet, permission)) && !(SET_CONTAINS(curPermissionsSet, permission))) {
                addedPermissions.push_back(permission);
            }
            if (!(SET_CONTAINS(permissionsSet, permission)) && (SET_CONTAINS(curPermissionsSet, permission))) {
                removedPermissions.push_back(permission);
            }

        }

        //adding missing permissions
        for (auto addedPermission : addedPermissions) {
            command = mSqlConnection->PrepareDataCommand(
                    Queries.at(QueryType::EAddAppPermissions));
            command->BindString(1, appId.c_str());
            command->BindString(2, pkgId.c_str());
            command->BindString(3, addedPermission);

            if (command->Step())
                LogPedantic(
                        "Unexpected SQLITE_ROW answer to query: " << QueryType::EAddAppPermissions);

            command->Reset();
            LogPedantic(
                    "Added appId: " << appId << ", pkgId: " << pkgId << ", permission: " << addedPermission);

        }

        //removing unwanted permissions
        for (auto removedPermission : removedPermissions) {
            command = mSqlConnection->PrepareDataCommand(
                    Queries.at(QueryType::ERemoveAppPermissions));
            command->BindString(1, appId.c_str());
            command->BindString(2, pkgId.c_str());
            command->BindString(3, removedPermission);

            if (command->Step())
                LogPedantic(
                        "Unexpected SQLITE_ROW answer to query: " << QueryType::EAddAppPermissions);

            LogPedantic(
                    "Removed appId: " << appId << ", pkgId: " << pkgId << ", permission: " << removedPermission);
        }

        return true;

    }CATCH_STANDARD_EXCEPTIONS;

    return false;
}
} //namespace SecurityServer
