/*
 * security-manager, database access
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
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
	EOperationFailed = 0, EOperationSuccessful
} TResult;

typedef enum {
	EGetAppPermissions,
	EAddAppPermissions,
	ERemoveAppPermissions,
	EAppIdExists,
	EPkgIdExists,
	EPermissionForIdExists,
	EPermissionForPkgIdExists,
	EBeginTransaction,
	ECommitTransaction,
	ERollbackTransaction
} TQueryType;

typedef std::map<TQueryType, const char * const > TQueries;

const TQueries Queries = {
		 { EGetAppPermissions, "SELECT * FROM app_permission_view WHERE app_name='%Q'" },
		 { EAddAppPermissions, "INSERT INTO app_permission_view (app_name, pkg_name, permission_name) VALUES (?, ?, ?)" },
		 { ERemoveAppPermissions, "DELETE FROM app_permission_view WHERE app_name=? AND pkg_name=? AND permission_name=?" },
		 { EAppIdExists, "SELECT * FROM app WHERE name=?" },
		 { EPkgIdExists, "SELECT * FROM pkg WHERE name=?" },
		 { EPermissionForPkgIdExists, "SELECT * FROM app_permission_view WHERE pkg_name=? AND permission_name=?" },
		 { EBeginTransaction, "BEGIN;"},
		 { ECommitTransaction, "COMMIT;"},
		 { ERollbackTransaction, "ROLLBACK;"}
		};

class PrivilegeDb {
	/**
	 * PrivilegeDb database class
	 */

private:
	SecurityServer::DB::SqlConnection *mSqlConnection;

public:
	PrivilegeDb(std::string Path);
	~PrivilegeDb(void);

    /**
     * Begin transaction
     *
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult BeginTransaction(void);

    /**
     * Commit transaction
     *
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult CommitTransaction(void);

    /**
     * Rollback transaction
     *
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult RollbackTransaction(void);

    /**
     * Check if appId is already registered in database
     *
     * @param appId - application identifier
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult AppIdExists(const char * const appId);

    /**
     * Check if pkgId is already registered in database
     *
     * @param pkgId - package identifier
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult PkgIdExists(const char * const pkgId);

    /**
     * Check if there's a tuple of (appId, packageId, permission) inside the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to check. This list is modified inside this method - existing
     * 						package ids are deleted from the list. Please pass a copy if You don't want Your
     * 						list modified.
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult PkgIdHasPermissions(const char * pkgId, TPermissionsList &permissions);

    /**
     * Add a tuple of (appId, packageId, permission) into the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to check. This list is modified inside this method - existing
     * 						package ids are deleted from the list. Please pass a copy if You don't want Your
     * 						list modified.
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult AddPermissions(const char *appId, const char *pkgId,
			TPermissionsList &permissions);

    /**
     * Remove a tuple of (appId, packageId, permission) from the database
     *
     * @param appId - application identifier
     * @param pkgId - package identifier
     * @param permissions - list of permissions to check
     * @return TResult::EOperationSuccessful on success, TResult::EOperationFailed on failure
     */
	TResult RemovePermissions(const char *appId, const char *pkgId,
			TPermissionsList &permissions);
};
}
;
//namespace SecurityServer

#endif // _DB_H_
