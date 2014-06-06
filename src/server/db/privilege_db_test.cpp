#include <exception>
#include <privilege_db.h>

using namespace SecurityServer;

PrivilegeDb *db;

typedef struct {
	const char *testName;
	bool result;
	const char *reason;
} TTestResult;

#define B2S(b) (b==true)?("PASSED"):("FAILED")
#define INIT_TESTS TTestResult result;
#define RUN_TEST(_name) testSetup (); \
						result = _name; \
						printf ("***\nNAME: %s, RESULT: %s, REASON: %s\n", result.testName, B2S(result.result), result.reason); \
						testCleanup ()

#define TEST_SUCCESS TTestResult {__FUNCTION__, true, ""}
#define TEST_SUCCESS_WITH_MESSAGE(msg) TTestResult {__FUNCTION__, true, msg}
#define TEST_FAILED TTestResult {__FUNCTION__, false, ""}
#define TEST_FAILED_WITH_MESSAGE(msg) TTestResult {__FUNCTION__, false, msg}
#define CLEANUP_TESTS

bool testSetup() {
	int ret = system ("sqlite3 rules.db < app-permissions-db.sql");
	if (!ret) return false;

	try {
		db = new PrivilegeDb("rules.db");
	} catch (SecurityServer::DB::SqlConnection::Exception::Base &e) {
		return false;
	};
	return true;
}

bool testCleanup() {

	if (db != NULL)
		delete db;

	int ret = system ("rm rules.db");
	if (!ret) return false;

	return true;
}

TTestResult test_Insert_1_App_Privilege() {
	TPermissionsList *list;
	list = new TPermissionsList();

	list->push_back("IAccess");
	list->push_back("WalkieTalkie");

	TResult ret = db->AddPermissions("123", "456", *list);

	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#1 AddPermissions failed");
	return TEST_SUCCESS;
}

TTestResult test_Insert_2_App_Privileges() {
	return TEST_SUCCESS;
}

TTestResult test_Insert_Null_App_Privilege() {
	return TEST_SUCCESS;
}

TTestResult test_Insert_Duplicate_App_Privilege() {
	TPermissionsList *list;
	list = new TPermissionsList();

	list->push_back("IAccess");
	list->push_back("WalkieTalkie");

	TResult ret = db->AddPermissions("123", "456", *list);

	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#1 AddPermissions failed");

	ret = db->AddPermissions("123", "456", *list);
	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#2 AddPermissions failed");

	printf ("Rozmiar listy: %d\n", list->size());

	if (list->size() == 0) return TEST_SUCCESS;
	return TEST_FAILED_WITH_MESSAGE ("Too many elements in list");
}

TTestResult test_Remove_App_Privilege() {
	TPermissionsList *list;
	list = new TPermissionsList();

	list->push_back("IAccess");
	list->push_back("WalkieTalkie");

	TResult ret = db->RemovePermissions("123", "456", *list);

	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("RemovePermissions failed");
	return TEST_SUCCESS;
}

TTestResult test_Check_Transaction_Rollback() {
	TPermissionsList list = TPermissionsList {"IAccess", "WalkieTalkie"};

	std::unique_ptr <TPermissionsList> tmpList = std::unique_ptr<TPermissionsList>(new TPermissionsList(list));

	db->BeginTransaction();

	TResult ret = db->AddPermissions("123", "456", *tmpList.get());
	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#1 AddPermissions failed");

	tmpList = std::unique_ptr<TPermissionsList>(new TPermissionsList(list));
	ret = db->AddPermissions("456", "123", *tmpList.get());
	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#2 AddPermissions failed");

	db->RollbackTransaction();

	tmpList = std::unique_ptr<TPermissionsList>(new TPermissionsList(list));
	ret= db->PkgIdHasPermissions("456", *tmpList.get());
	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#1 PkgIdHasPermissions failed");
	if (tmpList->size() != 2) return TEST_FAILED_WITH_MESSAGE ("#1 pkg permissions added");

	tmpList = std::unique_ptr<TPermissionsList>(new TPermissionsList(list));
	ret= db->PkgIdHasPermissions("123", *tmpList.get());
	if (ret == SecurityServer::TResult::EOperationFailed) return TEST_FAILED_WITH_MESSAGE ("#2 PkgIdHasPermissions failed");
	if (tmpList->size() != 2) return TEST_FAILED_WITH_MESSAGE ("#2 pkg permissions added");

	return TEST_SUCCESS;
}

int main(void) {

	INIT_TESTS;
	RUN_TEST(test_Insert_1_App_Privilege());
	RUN_TEST(test_Insert_Duplicate_App_Privilege());
	RUN_TEST(test_Remove_App_Privilege());
	RUN_TEST(test_Check_Transaction_Rollback());
	CLEANUP_TESTS;
}
;
