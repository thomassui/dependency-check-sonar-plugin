# Implementation Proposal: Revert from 3-Level to 5-Level Severity Mapping

## Problem Statement

The plugin currently maps CVSS scores to 3 SonarQube severity levels (HIGH, MEDIUM, LOW), but SonarQube has reverted back to supporting 5 severity levels (BLOCKER, CRITICAL, MAJOR, MINOR, INFO). This mismatch causes high-risk vulnerabilities (e.g., CVSS 9.8) to be reported as MAJOR instead of BLOCKER or CRITICAL, reducing visibility and impact.

## Current Implementation

### Configuration Properties
The plugin currently accepts 3 configurable severity thresholds:
```ini
sonar.dependencyCheck.severity.high=7.0      (maps to Severity.HIGH)
sonar.dependencyCheck.severity.medium=4.0    (maps to Severity.MEDIUM)
sonar.dependencyCheck.severity.low=0.0       (maps to Severity.LOW)
```

### Affected Files
1. **DependencyCheckConstants.java** - Defines severity configuration constants
2. **DependencyCheckUtils.java** - Contains `cvssToSonarQubeSeverity()` method that maps CVSS scores
3. **DependencyCheckConfiguration.java** - Defines the configuration UI
4. **DependencyCheckUtilsTest.java** - Test cases for severity mapping

## Proposed Solution

### 1. Update DependencyCheckConstants.java

Add new configuration constants for 5-level severity mapping:

```java
// New property definitions for 5-level mapping
public static final String SEVERITY_BLOCKER = "sonar.dependencyCheck.severity.blocker";
public static final String SEVERITY_CRITICAL = "sonar.dependencyCheck.severity.critical";
public static final String SEVERITY_MAJOR = "sonar.dependencyCheck.severity.major";
public static final String SEVERITY_MINOR = "sonar.dependencyCheck.severity.minor";
public static final String SEVERITY_INFO = "sonar.dependencyCheck.severity.info";

// Default thresholds (based on CVSS scoring)
public static final Float SEVERITY_BLOCKER_DEFAULT = 9.0f;   // Critical vulnerabilities
public static final Float SEVERITY_CRITICAL_DEFAULT = 7.0f;  // High severity
public static final Float SEVERITY_MAJOR_DEFAULT = 4.0f;     // Medium severity
public static final Float SEVERITY_MINOR_DEFAULT = 1.0f;     // Low severity
public static final Float SEVERITY_INFO_DEFAULT = 0.0f;      // Informational

// Keep old constants for backward compatibility (deprecated)
@Deprecated
public static final String SEVERITY_HIGH = "sonar.dependencyCheck.severity.high";
@Deprecated
public static final String SEVERITY_MEDIUM = "sonar.dependencyCheck.severity.medium";
@Deprecated
public static final String SEVERITY_LOW = "sonar.dependencyCheck.severity.low";

@Deprecated
public static final Float SEVERITY_HIGH_DEFAULT = 7.0f;
@Deprecated
public static final Float SEVERITY_MEDIUM_DEFAULT = 4.0f;
@Deprecated
public static final Float SEVERITY_LOW_DEFAULT = 0.0f;
```

### 2. Update DependencyCheckUtils.java

Replace the `cvssToSonarQubeSeverity()` method with a new 5-level implementation:

```java
/**
 * Maps CVSS scores to SonarQube 5-level severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
 * 
 * @param cvssScore the CVSS score to map
 * @param blocker minimum score for BLOCKER severity (>= this value)
 * @param critical minimum score for CRITICAL severity
 * @param major minimum score for MAJOR severity
 * @param minor minimum score for MINOR severity
 * @return SonarQube Severity level
 */
public static Severity cvssToSonarQubeSeverity(Float cvssScore, Float blocker, Float critical, Float major, Float minor) {
    if (blocker >= 0 && cvssScore >= blocker) {
        return Severity.BLOCKER;
    } else if (critical >= 0 && cvssScore >= critical) {
        return Severity.CRITICAL;
    } else if (major >= 0 && cvssScore >= major) {
        return Severity.MAJOR;
    } else if (minor >= 0 && cvssScore >= minor) {
        return Severity.MINOR;
    } else {
        return Severity.INFO;
    }
}

/**
 * Convenience method using configuration
 */
public static Severity cvssToSonarQubeSeverity(Float cvssScore, Configuration config) {
    Float severityBlocker = config.getFloat(DependencyCheckConstants.SEVERITY_BLOCKER)
        .orElse(DependencyCheckConstants.SEVERITY_BLOCKER_DEFAULT);
    Float severityCritical = config.getFloat(DependencyCheckConstants.SEVERITY_CRITICAL)
        .orElse(DependencyCheckConstants.SEVERITY_CRITICAL_DEFAULT);
    Float severityMajor = config.getFloat(DependencyCheckConstants.SEVERITY_MAJOR)
        .orElse(DependencyCheckConstants.SEVERITY_MAJOR_DEFAULT);
    Float severityMinor = config.getFloat(DependencyCheckConstants.SEVERITY_MINOR)
        .orElse(DependencyCheckConstants.SEVERITY_MINOR_DEFAULT);
    
    return cvssToSonarQubeSeverity(cvssScore, severityBlocker, severityCritical, severityMajor, severityMinor);
}

// Keep old method for backward compatibility (deprecated)
@Deprecated
public static Severity cvssToSonarQubeSeverity(Float cvssScore, Float high, Float medium) {
    // Map old 3-level to new 5-level:
    // HIGH (3-level) -> CRITICAL (5-level)
    // MEDIUM (3-level) -> MAJOR (5-level)
    // LOW (3-level) -> MINOR (5-level)
    return cvssToSonarQubeSeverity(cvssScore, -1f, high, medium, 0f);
}
```

### 3. Update DependencyCheckConfiguration.java

Add 5 new property definitions and deprecate the old 3-level properties:

```java
public static List<PropertyDefinition> getPropertyDefinitions() {
    return Arrays.asList(
        // ... existing JSON report path property ...
        
        // New 5-level severity definitions
        PropertyDefinition.builder(DependencyCheckConstants.SEVERITY_BLOCKER)
            .onConfigScopes(ConfigScope.PROJECT)
            .subCategory(DependencyCheckConstants.SUB_CATEGORY_SEVERITIES)
            .name("Blocker")
            .description("Minimum CVSS score for blocker issues or -1 to deactivate. Default: 9.0")
            .defaultValue(Float.toString(DependencyCheckConstants.SEVERITY_BLOCKER_DEFAULT))
            .type(PropertyType.FLOAT)
            .index(1)
            .build(),
        PropertyDefinition.builder(DependencyCheckConstants.SEVERITY_CRITICAL)
            .onConfigScopes(ConfigScope.PROJECT)
            .subCategory(DependencyCheckConstants.SUB_CATEGORY_SEVERITIES)
            .name("Critical")
            .description("Minimum CVSS score for critical issues or -1 to deactivate. Default: 7.0")
            .defaultValue(Float.toString(DependencyCheckConstants.SEVERITY_CRITICAL_DEFAULT))
            .type(PropertyType.FLOAT)
            .index(2)
            .build(),
        PropertyDefinition.builder(DependencyCheckConstants.SEVERITY_MAJOR)
            .onConfigScopes(ConfigScope.PROJECT)
            .subCategory(DependencyCheckConstants.SUB_CATEGORY_SEVERITIES)
            .name("Major")
            .description("Minimum CVSS score for major issues or -1 to deactivate. Default: 4.0")
            .defaultValue(Float.toString(DependencyCheckConstants.SEVERITY_MAJOR_DEFAULT))
            .type(PropertyType.FLOAT)
            .index(3)
            .build(),
        PropertyDefinition.builder(DependencyCheckConstants.SEVERITY_MINOR)
            .onConfigScopes(ConfigScope.PROJECT)
            .subCategory(DependencyCheckConstants.SUB_CATEGORY_SEVERITIES)
            .name("Minor")
            .description("Minimum CVSS score for minor issues or -1 to deactivate. Default: 1.0")
            .defaultValue(Float.toString(DependencyCheckConstants.SEVERITY_MINOR_DEFAULT))
            .type(PropertyType.FLOAT)
            .index(4)
            .build(),
        PropertyDefinition.builder(DependencyCheckConstants.SEVERITY_INFO)
            .onConfigScopes(ConfigScope.PROJECT)
            .subCategory(DependencyCheckConstants.SUB_CATEGORY_SEVERITIES)
            .name("Info")
            .description("Minimum CVSS score for info issues or -1 to deactivate. Default: 0.0")
            .defaultValue(Float.toString(DependencyCheckConstants.SEVERITY_INFO_DEFAULT))
            .type(PropertyType.FLOAT)
            .index(5)
            .build(),
        
        // ... rest of the properties ...
    );
}
```

### 4. Update Tests (DependencyCheckUtilsTest.java)

Add comprehensive test cases for 5-level mapping:

```java
@ParameterizedTest(name = "{index} => cvssScore={0}, blocker={1}, critical={2}, major={3}, minor={4}, expectedSeverity={5}")
@MethodSource("severities5Level")
void testCvssToSonarQubeSeverity5Level(Float cvssScore, Float blocker, Float critical, Float major, Float minor, Severity expectedSeverity) {
    assertEquals(expectedSeverity, DependencyCheckUtils.cvssToSonarQubeSeverity(cvssScore, blocker, critical, major, minor));
}

public static Stream<Object[]> severities5Level() {
    return Stream.of(
        // Default thresholds: blocker=9.0, critical=7.0, major=4.0, minor=1.0
        new Object[]{Float.valueOf("9.8"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.BLOCKER},
        new Object[]{Float.valueOf("9.0"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.BLOCKER},
        new Object[]{Float.valueOf("8.9"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.CRITICAL},
        new Object[]{Float.valueOf("7.0"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.CRITICAL},
        new Object[]{Float.valueOf("6.9"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.MAJOR},
        new Object[]{Float.valueOf("4.0"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.MAJOR},
        new Object[]{Float.valueOf("3.9"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.MINOR},
        new Object[]{Float.valueOf("1.0"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.MINOR},
        new Object[]{Float.valueOf("0.9"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.INFO},
        new Object[]{Float.valueOf("0.0"), Float.valueOf("9.0"), Float.valueOf("7.0"), Float.valueOf("4.0"), Float.valueOf("1.0"), Severity.INFO},
        // ... additional test cases for disabled levels, custom thresholds, etc ...
    );
}
```

### 5. Update README.md

Update documentation to reflect the new configuration:

```ini
# New 5-level severity configuration
sonar.dependencyCheck.severity.blocker=9.0
sonar.dependencyCheck.severity.critical=7.0
sonar.dependencyCheck.severity.major=4.0
sonar.dependencyCheck.severity.minor=1.0
sonar.dependencyCheck.severity.info=0.0
```

## Default Mapping

Based on CVSS v3 severity ratings and the issue report:

| CVSS Score | Severity  |
|------------|-----------|
| 9.0-10.0  | BLOCKER   |
| 7.0-8.9   | CRITICAL  |
| 4.0-6.9   | MAJOR     |
| 1.0-3.9   | MINOR     |
| 0.0-0.9   | INFO      |

## Backward Compatibility

- Keep old constants and methods marked as `@Deprecated`
- Deprecated methods will be removed in future major versions
- Plugin will prefer new 5-level configuration if specified
- Falls back to old 3-level configuration for existing setups

## Implementation Order

1. Update `DependencyCheckConstants.java` - Add new constants
2. Update `DependencyCheckUtils.java` - Implement new mapping logic
3. Update `DependencyCheckConfiguration.java` - Add new configuration UI
4. Update `DependencyCheckUtilsTest.java` - Add comprehensive tests
5. Update `README.md` - Document the changes
6. Test backward compatibility

## Testing Strategy

1. Unit tests for all 5-level severity mappings
2. Integration tests with sample CVSS scores
3. Backward compatibility tests with old 3-level configuration
4. Real-world test with Spring Boot 3.4.2 + CVE-2025-31651 (CVSS 9.8)
