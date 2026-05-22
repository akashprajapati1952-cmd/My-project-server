const multer = require('multer');

// टेम्परेरी डिस्क स्टोरेज कॉन्फ़िगरेशन
const storage = multer.diskStorage({});

const upload = multer({ 
  storage,
  limits: { fileSize: 1024 * 1024 * 5 } // मैक्सिमम 5MB की फाइल अपलोड लिमिट
});

module.exports = upload;
