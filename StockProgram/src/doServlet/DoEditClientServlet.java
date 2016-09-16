package doServlet;

import java.io.IOException;
import java.sql.Connection;
import java.sql.Date;
import java.sql.SQLException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import beans.Client;
import utils.MyUtils;
import utils.RepresentativeUtils;

@WebServlet(urlPatterns = {"/doEditClient"})
public class DoEditClientServlet extends HttpServlet{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public DoEditClientServlet(){
		super();
	}
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
		Connection conn = MyUtils.getStoredConnection(request);
		
		String firstName		= request.getParameter("lastName");
		String lastName 		= request.getParameter("firstName"); 
		String address 			= request.getParameter("address");
		String zipCodeStr		= request.getParameter("zipCode");
		String telephone		= request.getParameter("telephone");
		String email 			= request.getParameter("email");
		String ratingStr		= request.getParameter("rating");
		String creditCardNumber = request.getParameter("creditCardNumber");
		String idStr			= request.getParameter("id");
		Integer zipCode = null;
		Integer rating = null;
		Integer id = null;
		
		
		boolean hasError=false;
		String errorStrLastName, errorStrFirstName, errorStrAddress, errorStrZipCode, errorStrTelephone,
			errorStrEmail, errorStrRating, errorStrCreditCardNumber, errorStrId;

		Client client = null;
		
		// check for errors before updating the client		
		
		//LastName
		String regex, regex2;
		regex="[a-zA-Z]+";
		errorStrLastName=null;
		if(lastName==null || !lastName.matches(regex))
			errorStrLastName="Last Name invalid!";
		
		//FirstName
		errorStrFirstName=null;
		if(firstName==null || !firstName.matches(regex))
			errorStrFirstName="First Name invalid!";
		
		//Address
		regex="//w+";
		errorStrAddress=null;
		if(address==null || !address.matches(regex))
			errorStrAddress="Address invalid!";
		
		//Zip Code
		try{
			errorStrZipCode=null;
			zipCode = Integer.parseInt(zipCodeStr);
			if(zipCode<0 || zipCode>99999){
				hasError=true;
				errorStrZipCode = "Invalid Zip Code";
			}		
		}catch(Exception  e){
			hasError = true;
			errorStrZipCode="Invalid Zip Code!";
		}
		// Telephone
		regex="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]";
		regex2="[0-9][0-9][0-9]-[0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]";
		errorStrTelephone=null;
			telephone = request.getParameter("telephone");
		if(telephone==null|| (!telephone.matches(regex)&&!telephone.matches(regex2) )){
			hasError=true;
			errorStrTelephone="Invalid Telephone Number!";
		}
		//Email
		//regex="\\w+"; // this needs to be changed later
		errorStrEmail=null;
		if(email==null/*||!email.matches(regex)*/){
			hasError=true;
			errorStrEmail="Error: Invalid email!";
		}
		//Rating
		try{
			errorStrRating=null;
			rating = Integer.parseInt(ratingStr);
		}
		catch(Exception e){
			hasError=true;
			errorStrRating="Invalid Id!";
		}
		
		//Credit Card Number
		System.out.println(hasError);
		regex="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
				+"[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]";
		regex2="[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]"
				+"-[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]";
		errorStrCreditCardNumber=null;
		if(creditCardNumber == null || (!creditCardNumber.matches(regex)
				&& !creditCardNumber.matches(regex2) ) ){
			hasError=true;
			errorStrCreditCardNumber="Error: Invalid Credit Card!";
		}
		System.out.println(hasError);
		//Id
		try{
			errorStrId=null;
			id = Integer.parseInt(request.getParameter("id"));
		}
		catch(Exception e){
			hasError=true;
			errorStrId="Invalid Id!";
		}
		
		
		
		
		String errorString = null;
		
		if(!hasError){
			client = new Client(id, firstName, lastName, address, zipCode, telephone, email, rating, creditCardNumber);
			try{
				System.out.println("before update");
				RepresentativeUtils.updateClient(conn, client);
				System.out.println("after update");
			}
			catch(SQLException e){
				e.printStackTrace();
				hasError = true;
			}
		}
		//If there's an error, stay on Edit Client page
		if(hasError){
			client = new Client();
			//set errorString and employee then forward to views
			request.setAttribute("errorStrLastName", errorStrLastName);
			request.setAttribute("errorStrFirstName", errorStrFirstName);
			request.setAttribute("errorStrAddress", errorStrAddress);
			request.setAttribute("errorStrZipCode", errorStrZipCode);
			request.setAttribute("errorStrTelephone", errorStrTelephone);
			request.setAttribute("errorStrEmail", errorStrEmail);
			request.setAttribute("errorStrRating", errorStrRating);	request.setAttribute("errorStrId", errorStrId);
			request.setAttribute("errorStrCreditCardNumber", errorStrCreditCardNumber);
							
			request.setAttribute("lastName", lastName);
			request.setAttribute("firstName", firstName);
			request.setAttribute("address", address);
			request.setAttribute("zipCode", zipCodeStr);
			request.setAttribute("telephone", telephone);
			request.setAttribute("email", email);
			request.setAttribute("rating", ratingStr);
			request.setAttribute("creditCardNumber", creditCardNumber);
			request.setAttribute("id", idStr);
			request.setAttribute("client", client);	
			RequestDispatcher dispatcher = request.getServletContext()
					.getRequestDispatcher("/WEB-INF/views/editClientView.jsp");
			dispatcher.forward(request, response);
		}
		
		//If everything worked, redirect to the employeeList
		else{
			response.sendRedirect(request.getContextPath() + "/clientList");
		}
		
	}
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
	            throws ServletException, IOException {
	        doGet(request, response);
	    }
	
}