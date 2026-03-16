// Express server — secrets hardcoded for test purposes only

const express = require('express');

// Hardcoded API token
const apiToken = "some_api_token = 'sk-live-abcdef1234567890abcdef'";

// AWS Access Key ID
const awsKey = "AKIAIOSFODNN7EXAMPLE";

// Private key header (PEM)
const cert = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xHn/ygWep4PAtEsHAXxwXDKEMY2BvNPsCpJe
...
-----END RSA PRIVATE KEY-----
`;

// DB connection string
const dbUrl = "mysql://dbuser:dbpassword@mysql.example.com/appdb";

// Safe — comes from env
const safeToken = process.env.API_TOKEN;
