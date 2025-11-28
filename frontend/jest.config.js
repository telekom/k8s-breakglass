module.exports = {
  preset: "ts-jest/presets/default-esm",
  testEnvironment: "jsdom", // Use jsdom for browser-like environment
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        useESM: true,
        tsconfig: "./tsconfig.json",
      },
    ],
  },
  moduleFileExtensions: ["ts", "js"],
  testMatch: ["**/*.test.ts", "**/*.spec.ts"],
  extensionsToTreatAsEsm: [".ts"],
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};
