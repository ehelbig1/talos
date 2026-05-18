import { cn } from "../utils";

describe("cn utility", () => {
  it("concatenates truthy class names", () => {
    expect(cn("a", "b", "c")).toBe("a b c");
  });

  it("filters out falsy values", () => {
    // @ts-ignore intentionally passing falsy values
    expect(cn("a", false, null, undefined, "b")).toBe("a b");
  });
});
