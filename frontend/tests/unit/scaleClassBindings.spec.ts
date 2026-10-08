// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";

const sources = import.meta.glob("../../src/**/*.vue", { query: "?raw", import: "default", eager: true }) as Record<
  string,
  string
>;

/**
 * Stencil marks hydrated Scale elements with a `hydrated` class and hides the
 * rest. Vue rewrites the whole class attribute when a class binding changes,
 * which drops that flag and makes the element invisible (for example the
 * header theme toggle after the first click). State on Scale elements must use
 * attributes such as aria-pressed or data-* instead of class bindings.
 */
export function findScaleClassBindings(files: Record<string, string>): string[] {
  const offenders: string[] = [];
  for (const [file, source] of Object.entries(files)) {
    for (const match of source.matchAll(/<(scale-[\w-]+)\b([^>]*)>/g)) {
      if (/(?:^|\s)(?::|v-bind:)class=/.test(match[2] ?? "")) {
        const line = source.slice(0, match.index).split("\n").length;
        offenders.push(`${file.replace("../../", "")}:${line} <${match[1]}>`);
      }
    }
  }
  return offenders;
}

describe("Scale custom elements", () => {
  it("detects a dynamic class binding on a Scale element", () => {
    expect(
      findScaleClassBindings({
        "x.vue": `<scale-button\n  class="a"\n  :class="{ b: on }"\n>x</scale-button><div :class="c"></div>`,
      }),
    ).toEqual(["x.vue:1 <scale-button>"]);
  });

  it("never bind classes dynamically, so Stencil's hydrated flag survives updates", () => {
    expect(Object.keys(sources).length).toBeGreaterThan(10);
    expect(findScaleClassBindings(sources)).toEqual([]);
  });
});
