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

using namespace std;

namespace SecurityServer {

PrivilegeDb::PrivilegeDb(std::string Path) {
	try {
		mSqlConnection = new SecurityServer::DB::SqlConnection(Path,
				SecurityServer::DB::SqlConnection::Flag::None,
				SecurityServer::DB::SqlConnection::Flag::RW);
	} catch (SecurityServer::DB::SqlConnection::Exception::Base &e) {
		LogError("Database initialization error: " << e.DumpToString());
	};
}

PrivilegeDb::~PrivilegeDb() {
	delete mSqlConnection;
}
;

TResult PrivilegeDb::BeginTransaction(void) {
	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::EBeginTransaction));
		if (command->Step())
			LogPedantic("Unexpected result to query");
	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	}
	return TResult::EOperationSuccessful;
}

TResult PrivilegeDb::CommitTransaction(void) {
	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::ECommitTransaction));
		if (command->Step())
			LogPedantic("Unexpected result to query");
	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	}
	return TResult::EOperationSuccessful;
}

TResult PrivilegeDb::RollbackTransaction(void) {
	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::ERollbackTransaction));
		if (command->Step())
			LogPedantic("Unexpected result to query");
	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	}
	return TResult::EOperationSuccessful;
}

TResult PrivilegeDb::AppIdExists(const char * const appId) {

	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::EAppIdExists));
		command->BindString(1, appId);
		if (command->Step()) {
			LogPedantic("AppId: " << appId << " found in database");
			command->Reset();
			return TResult::EOperationSuccessful;
		};

	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	}

	return EOperationFailed;
}

TResult PrivilegeDb::PkgIdExists(const char * const pkgId) {

	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::EPkgIdExists));
		command->BindString(1, pkgId);
		if (command->Step()) {
			LogPedantic("PkgId: " << pkgId << " found in database");
			command->Reset();
			return TResult::EOperationSuccessful;
		};

	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	}

	return EOperationFailed;
}

TResult PrivilegeDb::PkgIdHasPermissions(const char * const pkgId,
		TPermissionsList &permissions, TPermissionsList *newPermissions) {

	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::EPermissionForPkgIdExists));
		for (TPermissionsList::iterator plIter = permissions.begin();
				plIter != permissions.end(); ++plIter) {
			command->BindString(1, pkgId);
			command->BindString(2, *plIter);
			//remove element from original list if database found an entry
			if (command->Step()) {
				LogPedantic(
						"PkgId: " << pkgId << " already has permission: " << *plIter <<" in database");
			} else {
				LogPedantic(
						"PkgId: " << pkgId << " doesn't have permission: " << *plIter <<" in database");
				newPermissions->push_back(*plIter);
			};

			command->Reset();
		}
	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	};

	return TResult::EOperationSuccessful;
}

TResult PrivilegeDb::AddPermissions(const char * const appId,
		const char * const pkgId, TPermissionsList &permissions,
		TPermissionsList *newPermissions) {

	TResult ret = this->PkgIdHasPermissions(pkgId, permissions, newPermissions);
	if (ret == TResult::EOperationFailed)
		return TResult::EOperationFailed;

	try {
		SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
				mSqlConnection->PrepareDataCommand(
						Queries.at(TQueryType::EAddAppPermissions));

		for (TPermissionsList::iterator plIter = permissions.begin();
				plIter != permissions.end(); ++plIter) {
			command->BindString(1, appId);
			command->BindString(2, pkgId);
			command->BindString(3, *plIter);

			if (command->Step()) {
				LogPedantic(
						"Unexpected SQLITE_ROW answer to query: " << TQueryType::EAddAppPermissions);
			};

			command->Reset();
			LogPedantic(
					"Added appId: " << appId << ", pkgId: " << pkgId << ", permission: " << *plIter);
		}
	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		//Internal error
		return TResult::EOperationFailed;
	}

	return TResult::EOperationSuccessful;
}

TResult PrivilegeDb::RemovePermissions(const char * const appId,
		const char * const pkgId, TPermissionsList &permissions) {

	try {
		for (TPermissionsList::iterator plIter = permissions.begin();
				plIter != permissions.end(); ++plIter) {
			SecurityServer::DB::SqlConnection::DataCommandAutoPtr command =
					mSqlConnection->PrepareDataCommand(
							Queries.at(TQueryType::ERemoveAppPermissions));
			command->BindString(1, appId);
			command->BindString(2, pkgId);
			command->BindString(3, *plIter);
			command->Step();
			LogPedantic(
					"Removed appId: " << appId << ", pkgId: " << pkgId << ", permission: " << *plIter);
		}
	} catch (SecurityServer::DB::SqlConnection::Exception::SyntaxError &e) {
		//Syntax error in command
		return TResult::EOperationFailed;
	} catch (SecurityServer::DB::SqlConnection::Exception::InternalError &e) {
		return TResult::EOperationFailed;
	}

	return TResult::EOperationSuccessful;
}

}

//namespace SecurityServer
