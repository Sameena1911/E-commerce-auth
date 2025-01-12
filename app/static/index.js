// document.getElementById("registerForm").addEventListener("submit", function(event) {
//   let password = document.getElementById("password").value;
//   let confirmPassword = document.getElementById("confirmPassword").value;

//   if (password !== confirmPassword) {
//       alert("Passwords do not match!");
//       event.preventDefault();
//   }

//   let contact = document.getElementById("contact").value;
//   if (!/^\d{10}$/.test(contact)) {
//       alert("Please enter a valid 10-digit contact number.");
//       event.preventDefault();
//   }
// });
// Register form validation
document.getElementById("registerForm").addEventListener("submit", function (event) {
    let name = document.getElementById("name").value;
    let email = document.getElementById("register-email").value;
    let password = document.getElementById("register-password").value;
    let confirmPassword = document.getElementById("confirm-password").value;
    let roleCustomer = document.getElementById("role-customer").checked;
    let roleDeliveryAgent = document.getElementById("role-delivery").checked;
    let contact = document.getElementById("contact").value;
    let location = document.getElementById("location").value;
    let dob = document.getElementById("dob").value;
    let genderMale = document.getElementById("gender-male").checked;
    let genderFemale = document.getElementById("gender-female").checked;
    let genderOther = document.getElementById("gender-other").checked;
  
    // Check all fields
    if (!name || !email || !password || !confirmPassword || !contact || !location || !dob) {
        alert("All fields are required!");
        event.preventDefault();
        return;
    }
  
    // Check password match
    if (password !== confirmPassword) {
        alert("Passwords do not match!");
        event.preventDefault();
        return;
    }
  
    // Check role
    if (!roleCustomer && !roleDeliveryAgent) {
        alert("Please select a role: Customer or Delivery Agent.");
        event.preventDefault();
        return;
    }
  
    // Check gender
    if (!genderMale && !genderFemale && !genderOther) {
        alert("Please select a gender.");
        event.preventDefault();
        return;
    }
  
    // Validate email format
    let emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        alert("Please enter a valid email address.");
        event.preventDefault();
        return;
    }
  
    // Validate contact number (10 digits)
    let contactRegex = /^\d{10}$/;
    if (!contactRegex.test(contact)) {
        alert("Please enter a valid 10-digit contact number.");
        event.preventDefault();
        return;
    }
  });
  
  // Login form validation
  document.getElementById("loginForm").addEventListener("submit", function (event) {
    let email = document.getElementById("email").value;
    let password = document.getElementById("password").value;
  
    if (!email || !password) {
        alert("Both fields are required!");
        event.preventDefault();
    }
  });
  
  // Forgot Password function
  function forgotPassword() {
    alert("Forgot Password functionality is not implemented yet!");
  }
  