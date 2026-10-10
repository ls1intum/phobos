import XCTest
import SwiftTestReporter
import ReferenceTests

_ = TestObserver()

var tests = [XCTestCaseEntry]()
tests += ReferenceTests.__allTests()

XCTMain(tests)
