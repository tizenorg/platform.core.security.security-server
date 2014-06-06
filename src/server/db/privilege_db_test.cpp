#include <exception>
#include <privilege_db.h>
#include <assert.h>

using namespace SecurityServer;

PrivilegeDb *db;
#define DATABASE_NAME "rules.db"

typedef struct {
    const char *fileName;
    const char *testName;
    int lineNumber;
    bool result;
    const char *reason;
} TTestResult;

#define B2S(b) (b==true)?("PASSED"):("FAILED")
#define INIT_TESTS TTestResult result;
#define RUN_TEST(_name) assert (testSetup () == true); \
						assert (db != NULL); \
						result = _name; \
						printf ("***\nNAME: %s, LINE: %d, FILE: %s, RESULT: %s, REASON: %s\n***\n", \
						result.testName, result.lineNumber, result.fileName, B2S(result.result), result.reason); \
						assert (testCleanup ())

#define TEST_SUCCESS TTestResult {__FILE__, __FUNCTION__, __LINE__, true, ""}
#define TEST_SUCCESS_WITH_MESSAGE(msg) TTestResult {__FILE__, __FUNCTION__, __LINE__, true, msg}
#define TEST_FAILED TTestResult {__FILE__, __FUNCTION__, __LINE__, false, ""}
#define TEST_FAILED_WITH_MESSAGE(msg) TTestResult {__FILE__, __FUNCTION__, __LINE__, false, msg}
#define CLEANUP_TESTS

bool testSetup() {
    int ret = system("/usr/bin/sqlite3 rules.db < app-permissions-db.sql");

    if (ret)
        printf("%s: %d\n", __FUNCTION__, ret);

    try {
        db = new PrivilegeDb(DATABASE_NAME);
        assert(db != NULL);
    } catch (SecurityServer::DB::SqlConnection::Exception::Base &e) {
        printf("Following exception occurred: %s", e.DumpToString().c_str());
        return false;
    };
    return true;
}

bool testCleanup() {

    if (db != NULL)
        delete db;

    int ret = system("rm rules.db");

    printf("%s: %d\n", __FUNCTION__, ret);

    if (ret)
        printf("%s: %d\n", __FUNCTION__, ret);

    return true;
}

TTestResult test_Insert_1_App_Privilege() {
    TPermissionsList *list = new TPermissionsList { "IAccess", "WalkieTalkie" };
    TPermissionsList *new_list = new TPermissionsList();
    std::string appId = "123";
    std::string pkgId = "456";

    bool ret = db->AddPermissions(appId, pkgId, *list, *new_list);

    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#1 AddPermissions failed");
    if (new_list->size() != 2)
        return TEST_FAILED_WITH_MESSAGE ("Database probably not empty");

    return TEST_SUCCESS;
}

TTestResult test_Insert_Duplicate_App_Privilege() {
    TPermissionsList *list = new TPermissionsList { "IAccess", "WalkieTalkie" };
    std::unique_ptr<TPermissionsList> newList = std::unique_ptr
            < TPermissionsList > (new TPermissionsList());
    std::string appId = "123";
    std::string pkgId = "456";

    bool ret = db->AddPermissions(appId, pkgId, *list, *newList.get());
    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#1 AddPermissions failed");
    if (newList.get()->size() != 2)
        return TEST_FAILED_WITH_MESSAGE ("There should be 2 elements in the list");

    newList = std::unique_ptr < TPermissionsList > (new TPermissionsList());
    ret = db->AddPermissions(appId, pkgId, *list, *newList.get());
    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#2 AddPermissions failed");

    if (newList.get()->size() == 0)
        return TEST_SUCCESS;
    return TEST_FAILED_WITH_MESSAGE ("Too many elements in list");
}

TTestResult test_Remove_App_Privilege() {
    TPermissionsList *list = new TPermissionsList { "IAccess", "WalkieTalkie" };
    list = new TPermissionsList();
    std::string appId = "123";
    std::string pkgId = "456";

    bool ret = db->RemovePermissions(appId, pkgId, *list);

    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("RemovePermissions failed");
    return TEST_SUCCESS;
}

TTestResult test_Check_Transaction_Rollback() {
    TPermissionsList list = TPermissionsList { "IAccess", "WalkieTalkie" };
    std::unique_ptr<TPermissionsList> newList = std::unique_ptr
            < TPermissionsList > (new TPermissionsList());
    std::string appId1 = "123";
    std::string pkgId1 = "456";
    std::string appId2 = "456";
    std::string pkgId2 = "123";

    db->BeginTransaction();

    bool ret = db->AddPermissions(appId1, pkgId1, list, *newList.get());
    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#1 AddPermissions failed");

    newList = std::unique_ptr < TPermissionsList > (new TPermissionsList());
    ret = db->AddPermissions(appId2, pkgId2, list, *newList.get());
    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#2 AddPermissions failed");

    db->RollbackTransaction();

    newList = std::unique_ptr < TPermissionsList > (new TPermissionsList());
    ret = db->PkgIdHasPermissions(pkgId1, list, *newList.get());
    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#1 PkgIdHasPermissions failed");
    if (newList.get()->size() != 2)
        return TEST_FAILED_WITH_MESSAGE ("#1 pkg permissions added");

    newList = std::unique_ptr < TPermissionsList > (new TPermissionsList());
    ret = db->PkgIdHasPermissions(pkgId2, list, *newList.get());
    if (!ret)
        return TEST_FAILED_WITH_MESSAGE ("#2 PkgIdHasPermissions failed");
    if (newList.get()->size() != 2)
        return TEST_FAILED_WITH_MESSAGE ("#2 pkg permissions added");

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
