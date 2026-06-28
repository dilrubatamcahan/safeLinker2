const { analyzeUrl } = require("./analyzer.js");

const url = process.argv[2];

if (!url) {
  console.error("URL yok");
  process.exit(1);
}

try {
  const result = analyzeUrl(url);
  console.log(JSON.stringify(result));
} catch (error) {
  console.error(error.message || String(error));
  process.exit(1);
}
