#include "test_example.h"

void ExampleTest::toUpper() {
    QString s("hello");
    QCOMPARE(s.toUpper(), QString("HELLO"));
}

QTEST_APPLESS_MAIN(ExampleTest)
