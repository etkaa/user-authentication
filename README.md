See it live : https://my-little-secret.herokuapp.com/

My-Little-Secret

This a simple authenticattion app built using MongoDB, Mongoose, Node.js, Express.js and EJS.

Mongoose userDB has two collections: userSchema and secretSchema. All users can access published secrets but only 
authenticated users are able to post a secret. Login or registration required to access to submit page. After user
logged in, a session cookie created to track authentication status of the user. Besides local Login strategies, 
app includes log in with Google and Facebook options, configured with Passport.js.

