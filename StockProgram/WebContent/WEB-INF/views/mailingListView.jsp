<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Client List</title>
</head>
<body>
	<table border="2" cellpadding="5" cellspacing="1">
	<tr>
		<th>Name</th>
		<th>Email</th>
		<th>Address</th>
		<th>City</th>
		<th>State</th>
		<th>Zip Code</th>
	</tr>
	<c:forEach items="${mailingListList}" var="mailingList">
		<tr>
			<td>${mailingList.name}</td>
			<td>${mailingList.email}</td>
			<td>${mailingList.address}</td>
			<td>${mailingList.city}</td>
			<td>${mailingList.state}</td>
			<td>${mailingList.zipCode}</td>
			
		</tr>
	
	</c:forEach>
	</table>
<a href="${pageContext.request.contextPath}/representative">Return to representative view</a>
</body>
</html>