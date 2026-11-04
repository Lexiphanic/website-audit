import { describe, expect, test } from "bun:test";
import { CHECK_DEFINITIONS } from "./registry";
import { scoreChecks } from "./score";
import type { CheckResult } from "./types";

function resultsFor(status: CheckResult["status"]): CheckResult[] {
  return CHECK_DEFINITIONS.map((definition) => ({
    key: definition.key,
    status,
    observed: status,
  }));
}

describe("scoreChecks", () => {
  test("all passes is 100 and grade A", () => {
    const score = scoreChecks(resultsFor("pass"));
    expect(score.overall).toBe(100);
    expect(score.grade).toBe("A");
    expect(score.coverage.checked).toBe(score.coverage.total);
  });

  test("all failures is 0 and grade F", () => {
    const score = scoreChecks(resultsFor("fail"));
    expect(score.overall).toBe(0);
    expect(score.grade).toBe("F");
  });

  test("warnings score half and grade E", () => {
    const score = scoreChecks(resultsFor("warn"));
    expect(score.overall).toBe(50);
    expect(score.grade).toBe("E");
  });

  test("skipped checks are excluded from coverage and the score", () => {
    const score = scoreChecks(resultsFor("skipped"));
    expect(score.overall).toBeNull();
    expect(score.grade).toBe("—");
    expect(score.coverage.checked).toBe(0);
  });
});
