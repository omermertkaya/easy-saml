const fs = require('fs');
const html = fs.readFileSync('views/admin.ejs', 'utf8').split('\n');

let depth = 0;
html.forEach((line, index) => {
    let oldDepth = depth;
    let opens = (line.match(/<div/g) || []).length;
    let closes = (line.match(/<\/div>/g) || []).length;
    depth += opens - closes;
    if (index > 36 && index < 65) {
        console.log(`${index + 1}: [${oldDepth}->${depth}] \t${line.trim()}`);
    }
    if (index >= 394 && index < 410) {
        console.log(`${index + 1}: [${oldDepth}->${depth}] \t${line.trim()}`);
    }
    if (index >= 455 && index < 469) {
        console.log(`${index + 1}: [${oldDepth}->${depth}] \t${line.trim()}`);
    }
});
