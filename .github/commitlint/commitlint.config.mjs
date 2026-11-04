// Commit messages follow Conventional Commits (https://www.conventionalcommits.org/) and carry a Signed-off-by line
// (the Developer Certificate of Origin, see CONTRIBUTING.md).
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "body-max-line-length": [2, "always", 116],   // the repository's line width
    "footer-max-line-length": [0],                 // trailers can hold long URLs
    "trailer-exists": [2, "always", "Signed-off-by:"],
  },
};
