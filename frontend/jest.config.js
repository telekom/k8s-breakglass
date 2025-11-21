module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "jsdom", // Use jsdom for browser-like environment
  transform: {
    "^.+\\.ts$": "ts-jest",
  },
  moduleFileExtensions: ["ts", "js"],
  testMatch: ["**/*.test.ts", "**/*.spec.ts"],
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};
