<%@ page language="java" contentType="text/html; charset=UTF-8"
  pageEncoding="UTF-8"%>
<!DOCTYPE html>
<html>
  <head>
     <meta charset="UTF-8">
     <title>Home Page</title>
  </head>
  <body>
 
    <h3> Basic Home Page </h3><br>

	<a href="${pageContext.request.contextPath}/manager"> Managers</a><br>
	<a href="${pageContext.request.contextPath}/representative">Customer Representatives</a><br>
	<a href="${pageContext.request.contextPath}/customer">Customers</a>
      
 
  </body>
</html>