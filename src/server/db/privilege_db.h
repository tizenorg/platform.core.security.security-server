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
 * @file        PrivilegeDb.h
 * @author      Krzysztof Sasiak (k.sasiak@samsung.com)
 * @version     1.0
 * @brief       This file contains declaration of the API to privilges database.
 */

#include <cstdio>
#include <list>
#include <map>
#include <stdbool.h>
#include <string>

#include <dpl/db/sql_connection.h>

#ifndef PRIVILEGE_DB_H_
#define PRIVILEGE_DB_H_

#define SET_CONTAINS(set,value) set.find(value)!=set.end()
#define STRINGIFY(x) x.c_str()
#define CATCH_STANDARD_EXCEPTIONS  \
    catch (DB::SqlConnection::Exception::SyntaxError &e) { \
        LogDebug("Syntax error in command: " << e.DumpToString()); \
        ThrowMsg(PrivilegeDb::Exception::InternalError, \
            "Syntax error in command: " << e.DumpToString()); \
    } catch (DB::SqlConnection::Exception::InternalError &e) { \
        LogDebug("Mysterious internal error in SqlConnection class" << e.DumpToString()); \
        ThrowMsg(PrivilegeDb::Exception::InternalError, \
            "Mysterious internal error in SqlConnection class: " << e.DumpToString()); \
    }

namespace SecurityServer {

typedef std::list<const char *> TPermissionsList;

enum class QueryType {
    EGetAppPermissions,
    EAddApplication,
    ERemoveApplication,
    EAddAppPermissions,
    ERemoveAppPermissions,
    EPkgIdExists,
    EPermissionForIdExists,
    EPermissionForPkgIdExists,
    EPermissionsForPkgId
};

class PrivilegeDb {
    /**
     * PrivilegeDb database class
     */

private:
    SecurityServer::DB::SqlConnection *mSqlConnection;
    const std::map<QueryType, const char * const > Queries = {
        { QueryType::EGetAppPermissions, "SELECT permission_name FROM app_permission_view WHERE app_name=? AND pkg_name=?"},
        { QueryType::EAddApplication, "INSERT INTO app_pkg_view (app_name, pkg_name) VALUES (?, ?)" },
        { QueryType::ERemoveApplication, "DELETE FROM app_pkg_view WHERE app_name=? AND pkg_name=?" },
        { QueryType::EAddAppPermissions, "INSERT INTO app_permission_view (app_name, pkg_name, permission_name) VALUES (?, ?, ?)" },
        { QueryType::ERemoveAppPermissions, "DELETE FROM app_permission_view WHERE app_name=? AND pkg_name=? AND permission_name=?" },
        { QueryType::EPkgIdExists, "SELECT * FROM pkg WHERE name=?" },
        { QueryType::EPermissionForPkgIdExists, "SELECT * FROM app_permission_view WHERE pkg_name=? AND permission_name=?" },
        { QueryType::EPermissionsForPkgId, "SELECT * FROM app_permission_view WHERE pkg_name=?" }
    };

    /**
     * Check if pkgId is already registered in database
     *
     * @param pkgId - package identifier
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @return true if pkgId exists in the database
     *
     */
    bool PkgIdExists(const std::string &pkgId);

    /**
     * Check if there's a tuple of (appId, packageId, permission) inside the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param currentPermissions - list of current permissions assigned to tuple (appId, pkgId)
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     * @return true on success, false on failure
     */
    bool GetAppPermissions(const std::string &appId, const std::string &pkgId,
            TPermissionsList &currentPermission);

public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(SecurityServer::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, IOError)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
    };

    /**
     * Constructor
     * @exception DB::SqlConnection::Exception::IOError on problems with database access
     *
     */
    PrivilegeDb(const std::string &path);
    ~PrivilegeDb(void);

    /**
     * Begin transaction
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     *
     */
    void BeginTransaction(void);

    /**
     * Commit transaction
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     *
     */
    void CommitTransaction(void);

    /**
     * Rollback transaction
     * @exception DB::SqlConnection::Exception::InternalError on internal error
     *
     */
    void RollbackTransaction(void);

    /**
     * Add an application into the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param pkgIdIsNew - return info if pkgId is new to the database
     * @return true on success, false on failure
     */
    bool AddApplication(const std::string &appId, const std::string &pkgId,
            bool &pkgIdIsNew);

    /**
     * Remove an application from the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param pkgIdIsNoMore - return info if pkgId is in the database
     * @return true on success, false on failure
     */
    bool RemoveApplication(const std::string &appId, const std::string &pkgId,
            bool &pkgIdIsNoMore);

    /**
     * Remove a tuple of (appId, packageId, permission) from the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to remove
     * @param addedPermissions - return list of new permissions
     * @param removedPermissions - return list of removed permissions
     * @return true on success, false on failure
     */
    bool UpdatePermissions(const std::string &appId,
            const std::string &pkgId, const TPermissionsList &permissions,
            TPermissionsList &addedPermissions,
            TPermissionsList &removedPermissions);

};
}
;
//namespace SecurityServer

#endif // PRIVILEGE_DB_H_
