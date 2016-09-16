<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
   <%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
 <head>
  	<meta charset="UTF-8">
  	<title>Edit Employee</title>
 </head>
<body>
	<h3>Edit Employee</h3>

	<c:if test="${not empty employee}">
	<form method="POST" action="doEditEmployee">
	  
	  <p style="color:red;">Employee Id: ${employee.id}</p>
	  <p style="color:red;">SSN: ${employee.SSN}</p>
	  <p style="color:red;">Start Date: ${employee.startDate}</p>
	  
	  <p style="color: red;">${errorStrFirstName}</p> 
	  First name:<br>
	  <input type="text" name="firstName" value="${employee.firstName}"><br>
	  
	  <p style="color: red;">${errorStrLastName}</p>
	  Last name:<br>
	  <input type="text" name="lastName" value="${employee.lastName}"><br>
  	  
  	 
  	  <input type="hidden" name="SSN" value="${employee.SSN}">
  	 
  	 
  	  <p style="color: red;">${errorStrAddress}</p>
  	  Address:<br>
  	  <input type="text" name="address"value="${employee.address}"><br>
  
  	  <p style="color: red;">${errorStrZipCode}</p>
  	  Zip Code:<br>
  	  <input type="number" name="zipCode" min="1" max="99999"value="${employee.zipCode}"><br>
  
  	  <p style="color: red;">${errorStrTelephone}</p>
  	  Telephone:<br>
  	  <input type="text" name= "telephone" min="1" max="9999999999" value="${employee.telephone}"><br>
  
  	  <input type="hidden" name="id" value="${employee.id}">
 
 	  <input type="hidden" name="startDate" value="${employee.startDate}">
 
  	  <p style="color: red;">${errorStrHourlyRate}</p>
  	  Hourly Rate<br>  
	  <input type="number" name="hourlyRate" min="1" value="${employee.hourlyRate}"><br>

  	  <input type="submit" value="Submit"/>
  	  <a href="${pageContext.request.contextPath}/employeeList">Return to employee list</a>
	</form>
	</c:if>
</body>
</html>