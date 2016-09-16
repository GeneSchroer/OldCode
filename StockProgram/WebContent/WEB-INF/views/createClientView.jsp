<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
   <%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
<h1>Create Client View</h1>
</head>
<body>
<p style="color: red;">${errorString}</p>
<form method="POST" action="doCreateClient">
  <p style="color: red;">${errorStrId}</p>
  ClientId:<br>
  <input type="number" name="id" min="1" max="999999999" value="${id}">
  <p style="color: red;">${errorStrFirstName}</p><br>
  First name:<br>
  <input type="text" name="firstName" value="${firstName}">
  <br>
  <p style="color: red;">${errorStrLastName}</p>
  Last name:<br>
  <input type="text" name="lastName" value="${lastName}">
  <br>
  <p style="color: red;">${errorStrAddress}</p>
  Address:<br>
  <input type="text" name="address"value="${address}"><br>
  <p style="color: red;">${errorStrZipCode}</p>
  Zip Code:<br>
  <input type="number" name="zipCode" min="1" max="99999"value="${zipCode}"><br>
  <p style="color: red;">${errorStrTelephone}</p>
  Telephone:<br>
  <input type="text" name= "telephone" min="1" max="9999999999" value="${telephone}"><br>
  <p style="color: red;">${errorStrEmail}</p>
  Email:<br>
  <input type="text" name="email" value="${email}"><br>
  <p style="color: red;">${errorStrRating}</p>
  Rating:<br>  
  <input type="number" name="rating" min="1" value="${rating}"><br>
  <p style="color: red;">${errorStrCreditCardNumber}</p>
  Credit Card Number:<br>  
  <input type="text" name="creditCardNumber" value="${creditCardNumber}"><br>
  

  <input type="submit" value="Submit"/>
  <a href = "${pageContext.request.contextPath}/clientList">Return to Client page</a>
</form>

</body>
</html>