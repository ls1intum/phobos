package de.phobos.reference;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.tum.cit.ase.ares.api.Policy;
import de.tum.cit.ase.ares.api.StrictTimeout;
import de.tum.cit.ase.ares.api.jupiter.PublicTest;

/**
 * The trusted test class of the reference exercise, named in {@code theFollowingClassesAreTestClasses}
 * of the policy. Two passing tests, so that a run that runs none of them is not mistaken for a pass.
 */
@Policy(value = "SecurityPolicy.yaml", withinPath = "classes/de/phobos/reference")
public class AdderTest {

    @PublicTest
    @StrictTimeout(10)
    void addsTwoNumbers() {
        assertEquals(5, Adder.add(2, 3));
    }

    @PublicTest
    @StrictTimeout(10)
    void addsANegativeNumber() {
        assertEquals(-1, Adder.add(2, -3));
    }
}
