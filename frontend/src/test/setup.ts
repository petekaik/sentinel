import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Vitest has no globals here, so RTL cannot register its automatic cleanup.
// Without this, a component's polling timer and DOM survive into the next test.
afterEach(cleanup);
