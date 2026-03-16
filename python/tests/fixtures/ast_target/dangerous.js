// Intentionally dangerous JavaScript for AST analyzer testing

function runDangerous(userInput) {
    // eval with user input — XSS / code injection
    eval(userInput);  // SEC-JS_EVAL

    // innerHTML assignment — XSS
    document.getElementById('output').innerHTML = userInput;  // SEC-JS_INNER_HTML

    // document.write — XSS
    document.write(userInput);  // SEC-JS_DOCUMENT_WRITE
}

// SQL via template literal — injection
function getUser(db, userId) {
    const query = `SELECT * FROM users WHERE id = ${userId}`;  // SEC-JS_SQL_TEMPLATE
    return db.query(query);
}

// Safe: eval with a literal string
const safeCalc = eval("1 + 2");

// Safe: textContent
document.getElementById('safe').textContent = userInput;
