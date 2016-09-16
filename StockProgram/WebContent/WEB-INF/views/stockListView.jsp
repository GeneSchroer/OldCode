<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
	<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Stock List</title>
</head>
<body>
	<table border="2" cellpadding="5" cellspacing="1">
		<tr>
			<th>Stock Symbol</th>
			<th>Company Name</th>
			<th>Type</th>
			<th>Price Per Share</th>
			<th>Update Share Price</th>
		</tr>
		<c:forEach items="${stockList}" var="stock">
			<tr>
				<td>${stock.stockSymbol}</td>
				<td>${stock.companyName}</td>
				<td>${stock.type}</td>
				<td>${stock.pricePerShare}</td>
				<td><a href="updateStockPrice?stockSymbol=${stock.stockSymbol}">Update</a>
			</tr>
		</c:forEach>
	</table>
	<a href="${pageContext.request.contextPath}/manager">Return to manager view</a>
</body>
</html>