<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
       <%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
  <head>
  <meta charset="UTF-8">
<title>Edit Client</title>
<h3>Edit Client</h3>
</head>
<body>
<c:if test="${not empty client}">
	<form method="POST" action="doEditClient">
	  
	  <p style="color:red;">Client Id: ${client.id}</p>
	  
	  <p style="color: red;">${errorStrFirstName}</p> 
	  First name:<br>
	  <input type="text" name="firstName" value="${client.firstName}"><br>
	  
	  <p style="color: red;">${errorStrLastName}</p>
	  Last name:<br>
	  <input type="text" name="lastName" value="${client.lastName}"><br>
  	  
  	 
  	  <input type="hidden" name="SSN" value="${client.SSN}">
  	 
  	 
  	  <p style="color: red;">${errorStrAddress}</p>
  	  Address:<br>
  	  <input type="text" name="address"value="${client.address}"><br>
  
  	  <p style="color: red;">${errorStrZipCode}</p>
  	  Zip Code:<br>
  	  <input type="number" name="zipCode" min="1" max="99999"value="${client.zipCode}"><br>
  
  	  <p style="color: red;">${errorStrTelephone}</p>
  	  Telephone:<br>
  	  <input type="text" name= "telephone" min="1" max="9999999999" value="${client.telephone}"><br>
  
  
  
  	  <input type="hidden" name="id" value="${client.id}">
 
  	  <p style="color: red;">${errorStrEmail}</p>
  	  Email:<br>  
	  <input type="text" name="email" value="${client.email}"><br>

	  <p style="color: red;">${errorStrRating}</p>
  	  Rating:<br>  
	  <input type="number" name="rating" value="${client.rating}"><br>
	  
	  <p style="color: red;">${errorStrCreditCardNumber}</p>
  	  Credit Card Number:<br>  
	  <input type="text" name="creditCardNumber" value="${client.creditCardNumber}"><br>
	  

  	  <input type="submit" value="Submit"/>
  	  <a href="${pageContext.request.contextPath}/clientList">Return to Client List</a>
	</form>
	</c:if>


</body>
</html>