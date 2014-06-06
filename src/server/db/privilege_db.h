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

#ifndef _DB_H_
#define _DB_H_

namespace SecurityServer {

typedef std::list<const char *> TPermissionsList;

typedef enum {
    EGetAppPermissions,
    EAddAppPermissions,
    ERemoveAppPermissions,
    EAppIdExists,
    EPkgIdExists,
    EPermissionForIdExists,
    EPermissionForPkgIdExists
} TQueryType;

class PrivilegeDb {
    /**
     * PrivilegeDb database class
     */

private:
    SecurityServer::DB::SqlConnection *mSqlConnection;
    const std::map<TQueryType, const char * const > Queries = {
        { EAddAppPermissions, "INSERT INTO app_permission_view (app_name, pkg_name, permission_name) VALUES (?, ?, ?)" },
        { ERemoveAppPermissions, "DELETE FROM app_permission_view WHERE app_name=? AND pkg_name=? AND permission_name=?" },
        { EPkgIdExists, "SELECT * FROM pkg WHERE name=?" },
        { EPermissionForPkgIdExists, "SELECT * FROM app_permission_view WHERE pkg_name=? AND permission_name=?" }
    };

public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(SecurityServer::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, IOError)
        DECLARE_EXCEPTION_TYPE(Base, InternalError)
    };

    PrivilegeDb(const std::string &path);
    ~PrivilegeDb(void);

    /**
     * Begin transaction
     *
     */
    void BeginTransaction(void);

    /**
     * Commit transaction
     *
     */
    void CommitTransaction(void);

    /**
     * Rollback transaction
     *
     */
    void RollbackTransaction(void);

    /**
     * Check if appId is already registered in database
     *
     * @param appId - application identifier
     * @return true on success, false on failure
     */
    bool AppIdExists(const std::string &appId);

    /**
     * Check if pkgId is already registered in database
     *
     * @param pkgId - package identifier
     * @return true on success, false on failure
     */
    bool PkgIdExists(const std::string &pkgId);

    /**
     * Check if there's a tuple of (appId, packageId, permission) inside the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to check. This list is modified inside this method - existing
     * 						package ids are deleted from the list. Please pass a copy if You don't want Your
     * 						list modified.
     * @param newPermissions - pointer to a TPermissionsList. Method will fill the list with permissions newly
     * 							added to database
     * @return true on success, false on failure
     */
    bool PkgIdHasPermissions(const std::string &pkgId,
            const TPermissionsList &permissions,
            TPermissionsList &newPermissions);

    /**
     * Add a tuple of (appId, packageId, permission) into the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to check. This list is modified inside this method - existing
     * 						package ids are deleted from the list. Please pass a copy if You don't want Your
     * 						list modified.
     * @param newPermissions - pointer to a TPermissionsList. Method will fill the list with permissions newly
     * 							added to database
     * @return true on success, false on failure
     */
    bool AddPermissions(const std::string &appId, const std::string &pkgId,
            const TPermissionsList &permissions,
            TPermissionsList &newPermissions);

    /**
     * Remove a tuple of (appId, packageId, permission) from the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to remove
     * @return true on success, false on failure
     */
    bool RemovePermissions(const std::string &appId, const std::string &pkgId,
            const TPermissionsList &permissions);
};
}
;
//namespace SecurityServer

#endif // _DB_H_
