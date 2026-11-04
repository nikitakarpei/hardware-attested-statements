// Commit messages follow Conventional Commits (https://www.conventionalcommits.org/) and carry a Signed-off-by line
// (the Developer Certificate of Origin, see CONTRIBUTING.md). Merge commits are skipped by the workflow (--no-merges).
export default {
  extends: ["@commitlint/config-conventional"],
  plugins: [
    {
      rules: {
        // A line anywhere in the message: git's own trailer parser stops at a "---" line, which Dependabot's
        // messages have above their sign-off.
        "signed-off": ({ raw }) => [/^Signed-off-by: .+ <.+>$/m.test(raw ?? ""), "message must have a Signed-off-by line"],
      },
    },
  ],
  rules: {
    "body-max-line-length": [2, "always", 116],   // the repository's line width
    "footer-max-line-length": [0],                 // trailers can hold long URLs
    "subject-case": [0],                           // Dependabot writes "Bump …"
    "signed-off": [2, "always"],
  },
};
