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
		<th>Id</th>
		<th>Last Name</th>
		<th>First Name</th>
		<th>Edit</th>
		<th>Delete</th>
	</tr>
	<c:forEach items="${clientList}" var="client">
		<tr>
			<td>${client.id}</td>
			<td>${client.lastName}</td>
			<td>${client.firstName}</td>
			<td><a href="editClient?id=${client.id}">Edit</a></td>
			<td><a href="deleteClient?id=${client.id}">Delete</a></td>
		</tr>
	
	</c:forEach>
	</table>
	 <a href="${pageContext.request.contextPath}/createClient">Add Client</a>
<a href="${pageContext.request.contextPath}/representative">Return to representative view</a>
</body>
</html>