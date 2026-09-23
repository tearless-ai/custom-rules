# Custom rules

Custom Semgrep rules for import into Cycode as custom SAST policies.

## juliet-c-cpp-rules

C and C++ security and code-quality rules, one rule per file, named `<rule-id>.yaml`.
Each rule carries its CWE in `metadata.cwe`, plus a `help` section with a summary and remediation guidance.
The rules run on Semgrep OSS (1.177.0 or later) and need no Semgrep Pro features.

### How the rules were validated

Every rule was measured against the [NIST Juliet Test Suite for C/C++ v1.3](https://samate.nist.gov/SARD/test-suites), using the flaw lines in its `manifest.xml` as ground truth.
A test case counts as **detected** when a rule tagged with the test case's CWE reports a finding of at most five lines that covers the manifest's flaw line.
A **false alarm** is a finding from a rule tagged with the test case's CWE inside one of the test case's fixed (`good*`) functions.
Rules were kept only when they detect real vulnerable code without firing on the fixed variants.

The rules describe genuine defect patterns and are meant to work on ordinary code.
They never match Juliet-specific artifacts such as `bad`/`good` function names, `FLAW`/`FIX` comments, or Juliet's control-flow helper functions.
Some rules also match Juliet's portability macros that are plain aliases of standard APIs (for example `ALLOCA` for `alloca` and `GETENV` for `getenv`), because a compiler would expand them to the same calls.
The one Juliet-specific name a rule recognizes is `stdThreadCreate`, the Juliet support library's thin wrapper around `pthread_create` and `CreateThread`, in the CWE-366 thread race rule.
Findings are reported at the defective code itself (the dangerous call, allocation, write or arithmetic), even where Juliet's manifest marks a nearby placeholder line instead.
For some CWEs this means the finding is in the right function but not on the manifest's exact line, so the detection rate below understates what the rules find.

### Coverage

| CWE | Name | Rules | Test cases | Detected | Detection rate | False alarms |
|---|---|---:|---:|---:|---:|---:|
| [CWE-15](https://cwe.mitre.org/data/definitions/15.html) | External Control of System or Configuration Setting | 4 | 48 | 30 | 62% | 0 |
| [CWE-23](https://cwe.mitre.org/data/definitions/23.html) | Relative Path Traversal | 4 | 2400 | 1500 | 62% | 0 |
| [CWE-36](https://cwe.mitre.org/data/definitions/36.html) | Absolute Path Traversal | 4 | 2400 | 1500 | 62% | 0 |
| [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | OS Command Injection | 4 | 4800 | 3000 | 62% | 0 |
| [CWE-90](https://cwe.mitre.org/data/definitions/90.html) | LDAP Injection | 4 | 480 | 300 | 62% | 0 |
| [CWE-114](https://cwe.mitre.org/data/definitions/114.html) | Process Control | 8 | 576 | 360 | 62% | 0 |
| [CWE-121](https://cwe.mitre.org/data/definitions/121.html) | Stack Based Buffer Overflow | 13 | 4944 | 3135 | 63% | 0 |
| [CWE-122](https://cwe.mitre.org/data/definitions/122.html) | Heap Based Buffer Overflow | 14 | 5922 | 3742 | 63% | 0 |
| [CWE-123](https://cwe.mitre.org/data/definitions/123.html) | Write What Where Condition | 1 | 144 | 63 | 44% | 0 |
| [CWE-124](https://cwe.mitre.org/data/definitions/124.html) | Buffer Underwrite | 2 | 2048 | 1012 | 49% | 0 |
| [CWE-126](https://cwe.mitre.org/data/definitions/126.html) | Buffer Overread | 5 | 1452 | 768 | 53% | 0 |
| [CWE-127](https://cwe.mitre.org/data/definitions/127.html) | Buffer Underread | 2 | 2048 | 1012 | 49% | 0 |
| [CWE-134](https://cwe.mitre.org/data/definitions/134.html) | Uncontrolled Format String | 7 | 2880 | 1800 | 62% | 0 |
| [CWE-176](https://cwe.mitre.org/data/definitions/176.html) | Improper Handling of Unicode Encoding | 1 | 48 | 19 | 40% | 0 |
| [CWE-188](https://cwe.mitre.org/data/definitions/188.html) | Reliance on Data Memory Layout | 2 | 36 | 36 | 100% | 0 |
| [CWE-190](https://cwe.mitre.org/data/definitions/190.html) | Integer Overflow | 1 | 3960 | 2556 | 65% | 0 |
| [CWE-191](https://cwe.mitre.org/data/definitions/191.html) | Integer Underflow | 2 | 2952 | 1895 | 64% | 0 |
| [CWE-194](https://cwe.mitre.org/data/definitions/194.html) | Unexpected Sign Extension | 1 | 1152 | 720 | 62% | 0 |
| [CWE-195](https://cwe.mitre.org/data/definitions/195.html) | Signed to Unsigned Conversion Error | 2 | 1152 | 654 | 57% | 0 |
| [CWE-196](https://cwe.mitre.org/data/definitions/196.html) | Unsigned to Signed Conversion Error | 1 | 18 | 18 | 100% | 0 |
| [CWE-197](https://cwe.mitre.org/data/definitions/197.html) | Numeric Truncation Error | 1 | 864 | 540 | 62% | 0 |
| [CWE-222](https://cwe.mitre.org/data/definitions/222.html) | Truncation of Security Relevant Information | 1 | 18 | 18 | 100% | 0 |
| [CWE-223](https://cwe.mitre.org/data/definitions/223.html) | Omission of Security Relevant Information | 1 | 18 | 18 | 100% | 0 |
| [CWE-242](https://cwe.mitre.org/data/definitions/242.html) | Use of Inherently Dangerous Function | 1 | 18 | 18 | 100% | 0 |
| [CWE-244](https://cwe.mitre.org/data/definitions/244.html) | Heap Inspection | 1 | 72 | 72 | 100% | 0 |
| [CWE-247](https://cwe.mitre.org/data/definitions/247.html) | Reliance on DNS Lookups in Security Decision | 1 | 18 | 18 | 100% | 0 |
| [CWE-252](https://cwe.mitre.org/data/definitions/252.html) | Unchecked Return Value | 3 | 630 | 630 | 100% | 0 |
| [CWE-253](https://cwe.mitre.org/data/definitions/253.html) | Incorrect Check of Function Return Value | 7 | 684 | 684 | 100% | 0 |
| [CWE-256](https://cwe.mitre.org/data/definitions/256.html) | Plaintext Storage of Password | 1 | 96 | 42 | 44% | 0 |
| [CWE-259](https://cwe.mitre.org/data/definitions/259.html) | Hard Coded Password | 3 | 96 | 96 | 100% | 0 |
| [CWE-272](https://cwe.mitre.org/data/definitions/272.html) | Least Privilege Violation | 3 | 252 | 252 | 100% | 0 |
| [CWE-273](https://cwe.mitre.org/data/definitions/273.html) | Improper Check for Dropped Privileges | 1 | 36 | 36 | 100% | 0 |
| [CWE-284](https://cwe.mitre.org/data/definitions/284.html) | Improper Access Control | 2 | 216 | 216 | 100% | 0 |
| [CWE-319](https://cwe.mitre.org/data/definitions/319.html) | Cleartext Tx Sensitive Info | 4 | 192 | 116 | 60% | 0 |
| [CWE-321](https://cwe.mitre.org/data/definitions/321.html) | Hard Coded Cryptographic Key | 1 | 96 | 44 | 46% | 0 |
| [CWE-325](https://cwe.mitre.org/data/definitions/325.html) | Missing Required Cryptographic Step | 3 | 72 | 54 | 75% | 0 |
| [CWE-327](https://cwe.mitre.org/data/definitions/327.html) | Use Broken Crypto | 2 | 54 | 54 | 100% | 0 |
| [CWE-328](https://cwe.mitre.org/data/definitions/328.html) | Reversible One Way Hash | 2 | 54 | 54 | 100% | 0 |
| [CWE-338](https://cwe.mitre.org/data/definitions/338.html) | Weak PRNG | 1 | 18 | 18 | 100% | 0 |
| [CWE-364](https://cwe.mitre.org/data/definitions/364.html) | Signal Handler Race Condition | 1 | 18 | 18 | 100% | 0 |
| [CWE-366](https://cwe.mitre.org/data/definitions/366.html) | Race Condition Within Thread | 1 | 36 | 36 | 100% | 0 |
| [CWE-367](https://cwe.mitre.org/data/definitions/367.html) | TOC TOU | 1 | 36 | 36 | 100% | 0 |
| [CWE-369](https://cwe.mitre.org/data/definitions/369.html) | Divide by Zero | 2 | 864 | 510 | 59% | 0 |
| [CWE-377](https://cwe.mitre.org/data/definitions/377.html) | Insecure Temporary File | 2 | 144 | 144 | 100% | 0 |
| [CWE-390](https://cwe.mitre.org/data/definitions/390.html) | Error Without Action | 2 | 90 | 90 | 100% | 0 |
| [CWE-391](https://cwe.mitre.org/data/definitions/391.html) | Unchecked Error Condition | 1 | 54 | 54 | 100% | 0 |
| [CWE-396](https://cwe.mitre.org/data/definitions/396.html) | Catch Generic Exception | 1 | 54 | 54 | 100% | 0 |
| [CWE-397](https://cwe.mitre.org/data/definitions/397.html) | Throw Generic Exception | 2 | 20 | 20 | 100% | 0 |
| [CWE-398](https://cwe.mitre.org/data/definitions/398.html) | Poor Code Quality | 9 | 181 | 180 | 99% | 0 |
| [CWE-400](https://cwe.mitre.org/data/definitions/400.html) | Resource Exhaustion | 1 | 720 | 450 | 62% | 0 |
| [CWE-401](https://cwe.mitre.org/data/definitions/401.html) | Memory Leak | 8 | 1658 | 108 | 7% | 0 |
| [CWE-404](https://cwe.mitre.org/data/definitions/404.html) | Improper Resource Shutdown | 1 | 384 | 368 | 96% | 0 |
| [CWE-415](https://cwe.mitre.org/data/definitions/415.html) | Double Free | 8 | 962 | 276 | 29% | 0 |
| [CWE-416](https://cwe.mitre.org/data/definitions/416.html) | Use After Free | 3 | 459 | 398 | 87% | 0 |
| [CWE-426](https://cwe.mitre.org/data/definitions/426.html) | Untrusted Search Path | 5 | 192 | 104 | 54% | 0 |
| [CWE-427](https://cwe.mitre.org/data/definitions/427.html) | Uncontrolled Search Path Element | 4 | 480 | 300 | 62% | 0 |
| [CWE-440](https://cwe.mitre.org/data/definitions/440.html) | Expected Behavior Violation | 1 | 1 | 1 | 100% | 0 |
| [CWE-457](https://cwe.mitre.org/data/definitions/457.html) | Use of Uninitialized Variable | 7 | 948 | 774 | 82% | 0 |
| [CWE-459](https://cwe.mitre.org/data/definitions/459.html) | Incomplete Cleanup | 1 | 36 | 0 | 0% | 0 |
| [CWE-464](https://cwe.mitre.org/data/definitions/464.html) | Addition of Data Structure Sentinel | 1 | 48 | 22 | 46% | 0 |
| [CWE-467](https://cwe.mitre.org/data/definitions/467.html) | Use of sizeof on Pointer Type | 1 | 54 | 54 | 100% | 0 |
| [CWE-468](https://cwe.mitre.org/data/definitions/468.html) | Incorrect Pointer Scaling | 2 | 37 | 37 | 100% | 0 |
| [CWE-469](https://cwe.mitre.org/data/definitions/469.html) | Use of Pointer Subtraction to Determine Size | 1 | 36 | 36 | 100% | 0 |
| [CWE-475](https://cwe.mitre.org/data/definitions/475.html) | Undefined Behavior for Input to API | 1 | 36 | 36 | 100% | 0 |
| [CWE-476](https://cwe.mitre.org/data/definitions/476.html) | NULL Pointer Dereference | 4 | 348 | 236 | 68% | 0 |
| [CWE-478](https://cwe.mitre.org/data/definitions/478.html) | Missing Default Case in Switch | 1 | 18 | 18 | 100% | 0 |
| [CWE-479](https://cwe.mitre.org/data/definitions/479.html) | Signal Handler Use of Non Reentrant Function | 1 | 18 | 18 | 100% | 0 |
| [CWE-480](https://cwe.mitre.org/data/definitions/480.html) | Use of Incorrect Operator | 1 | 18 | 18 | 100% | 0 |
| [CWE-481](https://cwe.mitre.org/data/definitions/481.html) | Assigning Instead of Comparing | 1 | 18 | 18 | 100% | 0 |
| [CWE-482](https://cwe.mitre.org/data/definitions/482.html) | Comparing Instead of Assigning | 1 | 18 | 18 | 100% | 0 |
| [CWE-483](https://cwe.mitre.org/data/definitions/483.html) | Incorrect Block Delimitation | 3 | 20 | 20 | 100% | 0 |
| [CWE-484](https://cwe.mitre.org/data/definitions/484.html) | Omitted Break Statement in Switch | 1 | 18 | 18 | 100% | 0 |
| [CWE-500](https://cwe.mitre.org/data/definitions/500.html) | Public Static Field Not Final | 1 | 1 | 1 | 100% | 0 |
| [CWE-506](https://cwe.mitre.org/data/definitions/506.html) | Embedded Malicious Code | 6 | 158 | 158 | 100% | 0 |
| [CWE-510](https://cwe.mitre.org/data/definitions/510.html) | Trapdoor | 2 | 70 | 53 | 76% | 0 |
| [CWE-511](https://cwe.mitre.org/data/definitions/511.html) | Logic Time Bomb | 1 | 72 | 72 | 100% | 0 |
| [CWE-526](https://cwe.mitre.org/data/definitions/526.html) | Info Exposure Environment Variables | 1 | 18 | 18 | 100% | 0 |
| [CWE-534](https://cwe.mitre.org/data/definitions/534.html) | Info Exposure Debug Log | 1 | 36 | 36 | 100% | 0 |
| [CWE-535](https://cwe.mitre.org/data/definitions/535.html) | Info Exposure Shell Error | 1 | 36 | 36 | 100% | 0 |
| [CWE-546](https://cwe.mitre.org/data/definitions/546.html) | Suspicious Comment | 1 | 90 | 90 | 100% | 0 |
| [CWE-561](https://cwe.mitre.org/data/definitions/561.html) | Dead Code | 2 | 2 | 2 | 100% | 0 |
| [CWE-562](https://cwe.mitre.org/data/definitions/562.html) | Return of Stack Variable Address | 2 | 3 | 3 | 100% | 0 |
| [CWE-563](https://cwe.mitre.org/data/definitions/563.html) | Unused Variable | 2 | 512 | 156 | 30% | 0 |
| [CWE-570](https://cwe.mitre.org/data/definitions/570.html) | Expression Always False | 6 | 16 | 11 | 69% | 0 |
| [CWE-571](https://cwe.mitre.org/data/definitions/571.html) | Expression Always True | 6 | 16 | 11 | 69% | 0 |
| [CWE-587](https://cwe.mitre.org/data/definitions/587.html) | Assignment of Fixed Address to Pointer | 1 | 18 | 18 | 100% | 0 |
| [CWE-588](https://cwe.mitre.org/data/definitions/588.html) | Attempt to Access Child of Non Structure Pointer | 1 | 80 | 44 | 55% | 0 |
| [CWE-590](https://cwe.mitre.org/data/definitions/590.html) | Free Memory Not on Heap | 6 | 2680 | 1675 | 62% | 0 |
| [CWE-591](https://cwe.mitre.org/data/definitions/591.html) | Sensitive Data Storage in Improperly Locked Memory | 1 | 96 | 94 | 98% | 0 |
| [CWE-605](https://cwe.mitre.org/data/definitions/605.html) | Multiple Binds Same Port | 1 | 18 | 18 | 100% | 0 |
| [CWE-606](https://cwe.mitre.org/data/definitions/606.html) | Unchecked Loop Condition | 1 | 480 | 300 | 62% | 0 |
| [CWE-615](https://cwe.mitre.org/data/definitions/615.html) | Info Exposure by Comment | 1 | 18 | 18 | 100% | 0 |
| [CWE-617](https://cwe.mitre.org/data/definitions/617.html) | Reachable Assertion | 3 | 306 | 132 | 43% | 0 |
| [CWE-620](https://cwe.mitre.org/data/definitions/620.html) | Unverified Password Change | 1 | 18 | 18 | 100% | 0 |
| [CWE-665](https://cwe.mitre.org/data/definitions/665.html) | Improper Initialization | 2 | 193 | 0 | 0% | 0 |
| [CWE-666](https://cwe.mitre.org/data/definitions/666.html) | Operation on Resource in Wrong Phase of Lifetime | 3 | 90 | 90 | 100% | 0 |
| [CWE-674](https://cwe.mitre.org/data/definitions/674.html) | Uncontrolled Recursion | 2 | 2 | 2 | 100% | 0 |
| [CWE-675](https://cwe.mitre.org/data/definitions/675.html) | Duplicate Operations on Resource | 1 | 192 | 51 | 27% | 0 |
| [CWE-676](https://cwe.mitre.org/data/definitions/676.html) | Use of Potentially Dangerous Function | 1 | 18 | 18 | 100% | 0 |
| [CWE-680](https://cwe.mitre.org/data/definitions/680.html) | Integer Overflow to Buffer Overflow | 1 | 576 | 264 | 46% | 0 |
| [CWE-681](https://cwe.mitre.org/data/definitions/681.html) | Incorrect Conversion Between Numeric Types | 1 | 54 | 54 | 100% | 0 |
| [CWE-685](https://cwe.mitre.org/data/definitions/685.html) | Function Call With Incorrect Number of Arguments | 1 | 18 | 18 | 100% | 0 |
| [CWE-688](https://cwe.mitre.org/data/definitions/688.html) | Function Call With Incorrect Variable or Reference as Argument | 1 | 18 | 18 | 100% | 0 |
| [CWE-690](https://cwe.mitre.org/data/definitions/690.html) | NULL Deref From Return | 1 | 960 | 560 | 58% | 0 |
| [CWE-758](https://cwe.mitre.org/data/definitions/758.html) | Undefined Behavior | 4 | 581 | 581 | 100% | 0 |
| [CWE-761](https://cwe.mitre.org/data/definitions/761.html) | Free Pointer Not at Start of Buffer | 1 | 576 | 576 | 100% | 0 |
| [CWE-762](https://cwe.mitre.org/data/definitions/762.html) | Mismatched Memory Management Routines | 9 | 3564 | 2232 | 63% | 0 |
| [CWE-773](https://cwe.mitre.org/data/definitions/773.html) | Missing Reference to Active File Descriptor or Handle | 1 | 144 | 83 | 58% | 0 |
| [CWE-775](https://cwe.mitre.org/data/definitions/775.html) | Missing Release of File Descriptor or Handle | 2 | 144 | 0 | 0% | 0 |
| [CWE-780](https://cwe.mitre.org/data/definitions/780.html) | Use of RSA Algorithm Without OAEP | 2 | 18 | 18 | 100% | 0 |
| [CWE-785](https://cwe.mitre.org/data/definitions/785.html) | Path Manipulation Function Without Max Sized Buffer | 1 | 18 | 18 | 100% | 0 |
| [CWE-789](https://cwe.mitre.org/data/definitions/789.html) | Uncontrolled Mem Alloc | 1 | 960 | 600 | 62% | 0 |
| [CWE-832](https://cwe.mitre.org/data/definitions/832.html) | Unlock of Resource That is Not Locked | 1 | 18 | 18 | 100% | 0 |
| [CWE-835](https://cwe.mitre.org/data/definitions/835.html) | Infinite Loop | 3 | 6 | 6 | 100% | 0 |
| [CWE-843](https://cwe.mitre.org/data/definitions/843.html) | Type Confusion | 1 | 80 | 44 | 55% | 0 |
| **All** | | **286** | **63962** | **39785** | **62%** | **0** |

### Known limitations

Semgrep OSS analyzes data flow within a single file.
Juliet flow variants that pass data across files (for example variants 22, 51-54, 61-68, 72-74 and 81-84) have vulnerable and fixed sinks that are syntactically identical, so the rules do not attempt them rather than raise false alarms.
This caps detection at roughly 50-65% for the large categories.

A few rules carry two CWE tags because the code they match cannot tell the two apart (for example relative vs absolute path traversal, or a stack vs heap source buffer), so per-CWE rule counts add up to more than the total.

Three Juliet CWEs (137 test cases) have no rule yet and are not in the table.
CWE-226 and CWE-667 mark the flaw on a comment line at the end of a block, which a finding reported at the real defect cannot cover; rules for them were deferred rather than tailored to that line.
For CWE-672 the vulnerable and fixed code are identical and differ only in the data, so any rule would flag both.

Semgrep reports an "Internal matching error" warning when `cwe563-overwritten-before-read` runs on some C++ files, mostly files that contain only class constructors and destructors.
This is a Semgrep engine limitation: the rule skips those files, and no other rule or result is affected.
On the full Juliet suite it produces about 4,600 such warnings.

### Re-importing an unchanged rule

Cycode rejects a custom policy whose content hashes identically to an existing one.
To force a re-import of a rule whose logic has not changed, add or bump a `cycode_rev` value under its `metadata`.
