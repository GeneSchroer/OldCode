<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
   <%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Add Employee</title>
Create Employee View

</head>
<body>
<p style="color: red;">${errorString}</p>
<form method="POST" action="doCreateEmployee">
  <p style="color: red;">${errorStrFirstName}</p>
  First name:<br>
  <input type="text" name="firstName" value="${firstName}">
  <br>
  <p style="color: red;">${errorStrLastName}</p>
  Last name:<br>
  <input type="text" name="lastName" value="${lastName}">
  <br>
  <p style="color: red;">${errorStrSSN}</p>
  SSN:<br>
  <input type="number" name="SSN" min="1" max="999999999" value="${SSN}">
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
  <p style="color: red;">${errorStrId}</p>
  Employee Id:<br>
  <input type="number" name="id" min="1" max="999999999" value="${id}"><br>
  <p style="color: red;">${errorStrStartDate}</p>
  Date:<br>
  <input type="date" name="startDate" value="${startDate}"><br>
  <p style="color: red;">${errorStrHourlyRate}</p>
  Hourly Rate<br>  
<input type="number" name="hourlyRate" min="1" value="${hourlyRate}"><br>

  <input type="submit" value="Submit"/>
  <a href = "${pageContext.request.contextPath}/manager">Return to manager page</a>
</form>

</body>
</html>