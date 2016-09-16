<%@ page language="java" contentType="text/html; charset=UTF-8"
    pageEncoding="UTF-8"%>
	 <%@ taglib uri = "http://java.sun.com/jsp/jstl/core" prefix="c" %>
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
	<h3>Update Stock</h3>
	<c:if test="${not empty stock}">
	<form method="POST" action="doUpdateStock">
	<p style="color: red;">${errorStrPPS}</p><br>
	<p>Update Stock:</p>
	<input type="hidden" name="stockSymbol" value="${stock.stockSymbol}"/>
	<input type="hidden" name="companyName" value="${stock.companyName}"/>
	<input type="hidden" name="type" value="${stock.type}"/>
	<input type="text" name="pricePerShare" value="${stock.pricePerShare}"/><br>
	<input type="submit" value="Submit"/>
	
	</form>
	</c:if>
</body>
</html>