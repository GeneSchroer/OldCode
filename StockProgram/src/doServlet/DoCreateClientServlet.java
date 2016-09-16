package doServlet;

import java.io.IOException;
import java.sql.Connection;
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

@WebServlet(urlPatterns = {"/doCreateClient"})
public class DoCreateClientServlet extends HttpServlet{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public DoCreateClientServlet(){
		super();
	}
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
		Connection conn = MyUtils.getStoredConnection(request);
		
		
		//declare and define variables
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
		
		// check for errors before adding an Employee to the database
		
		//LastName
		String regex=null;
		regex="[a-zA-Z]+";
		errorStrLastName=null;
		if(lastName==null || !lastName.matches(regex))
			errorStrLastName="Last Name invalid!";
		
		//FirstName
		errorStrFirstName=null;
		if(firstName==null || !firstName.matches(regex))
			errorStrFirstName="First Name invalid!";
		
		//Address
		address = request.getParameter("address");
		regex="\\w+";
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
		errorStrTelephone =null;
		if(telephone==null||!telephone.matches(regex)){
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
			rating = Integer.parseInt(request.getParameter("id"));
		}
		catch(Exception e){
			hasError=true;
			errorStrRating="Invalid Id!";
		}
		
		//Credit Card Number

		regex="[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]"
				+"[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]";
		errorStrCreditCardNumber=null;
		if(creditCardNumber == null || !creditCardNumber.matches(regex)){
			hasError=true;
			errorStrCreditCardNumber="Error: Invalid Credit Card!";
		}
		

		//Id
		try{
			errorStrId=null;
			id = Integer.parseInt(request.getParameter("id"));
			if(id<0 || id>999999999){
				errorStrId="Error: Invalid Id";
			}
			if(RepresentativeUtils.findPerson(conn, id)!=null){
				hasError=true;
				errorStrId="Error: Id already exists";
			}
		}
		catch(Exception e){
			hasError=true;
			errorStrId="Invalid Id!";
		}
			

		

		if(!hasError){
			client = new Client(id, firstName, lastName, address, zipCode, telephone, email, rating, creditCardNumber);
			try{
				RepresentativeUtils.addClient(conn, client);
			}
			catch(SQLException e){
				e.printStackTrace();
				hasError = true;
			}
		}
		
		//If there's an error, stay on createClientView
		if(hasError){
		//set errorString and employee then forward to views
		request.setAttribute("errorStrLastName", errorStrLastName);
		request.setAttribute("errorStrFirstName", errorStrFirstName);
		request.setAttribute("errorStrAddress", errorStrAddress);
		request.setAttribute("errorStrZipCode", errorStrZipCode);
		request.setAttribute("errorStrTelephone", errorStrTelephone);
		request.setAttribute("errorStrEmail", errorStrEmail);
		request.setAttribute("errorStrRating", errorStrRating);	request.setAttribute("errorStrId", errorStrId);
		request.setAttribute("errorStrCreditCardNumber", errorStrCreditCardNumber);
		request.setAttribute("errorStrId", errorStrId);
			
		
		request.setAttribute("lastName", lastName);
		request.setAttribute("firstName", firstName);
		request.setAttribute("address", address);
		request.setAttribute("zipCode", zipCodeStr);
		request.setAttribute("telephone", telephone);
		request.setAttribute("email", email);
		request.setAttribute("rating", ratingStr);
		request.setAttribute("creditCardNumber", creditCardNumber);
		request.setAttribute("id", idStr);
		

		
			RequestDispatcher dispatcher = request.getServletContext()
					.getRequestDispatcher("/WEB-INF/views/createClientView.jsp");
			dispatcher.forward(request, response);
		}
		
		//If everything worked, redirect to the clientList
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