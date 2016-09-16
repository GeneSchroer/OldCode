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

import beans.Employee;
import utils.ManagerUtils;
import utils.MyUtils;

@WebServlet(urlPatterns = {"/manager/employeeList/doCreateEmployee"})
public class DoCreateEmployeeServlet extends HttpServlet{
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public DoCreateEmployeeServlet(){
		super();
	}
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
		Connection conn = MyUtils.getStoredConnection(request);
		
		String firstName = request.getParameter("firstName");
		String lastName = request.getParameter("lastName");
		String address = request.getParameter("address");
		int SSN=0;
		int zipCode=0;
		String telephone=null;
		int id =0;
		int hourlyRate = 0;
		Date startDate=null;
		boolean hasError=false;
		String errorStrSSN, errorStrLastName, errorStrFirstName, errorStrAddress, errorStrZipCode, errorStrTelephone,
			errorStrId, errorStrStartDate, errorStrHourlyRate;

		Employee employee=null;
		
		// check for errors before adding an Employee to the database
		
		//SSN
		// Check if user input is an integer
		try{
			errorStrSSN=null;
			SSN = Integer.parseInt(request.getParameter("SSN"));
			if(SSN<0 || SSN>999999999){
				hasError=true;
				errorStrSSN="Invalid SSN!";
			}
				
		}catch(Exception e){
			
			hasError = true;
			errorStrSSN="Invalid SSN!";
		}
		
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
		regex="//w+";
		errorStrAddress=null;
		if(address==null || !address.matches(regex))
			errorStrAddress="Address invalid!";
		
		//Zip Code
		try{
			errorStrZipCode=null;
			zipCode = Integer.parseInt(request.getParameter("zipCode"));
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
		errorStrTelephone=null;
			telephone = request.getParameter("telephone");
		if(telephone==null||!telephone.matches(regex)){
			hasError=true;
			errorStrTelephone="Invalid Telephone Number!";
		}
		
		
		//Id
		try{
			errorStrId=null;
			id = Integer.parseInt(request.getParameter("id"));
		}
		catch(Exception e){
			hasError=true;
			errorStrId="Invalid Id!";
		}
		
		//Start Date
		try{			
			errorStrStartDate=null;
			startDate = Date.valueOf(request.getParameter("startDate"));
			//if(startDate.after(now))
			//(fix later)		
		}
		
		catch(Exception e){
			hasError=true;
			errorStrStartDate="Invalid Date!";
		}
		
		//Hourly Rate
		try{
			errorStrHourlyRate=null;
			hourlyRate = Integer.parseInt(request.getParameter("hourlyRate"));
			if(hourlyRate<0){
				errorStrHourlyRate="Invalid Hourly Rate";
			}
		}
		catch(Exception e){
			hasError=true;
			errorStrHourlyRate="Invalid Id!";
		}
		
		String errorString = null;
		

		if(!hasError){
			employee = new Employee(SSN, firstName, lastName, address, zipCode, telephone, id, startDate, hourlyRate );
			try{
				ManagerUtils.addEmployee(conn, employee);
			}
			catch(SQLException e){
				e.printStackTrace();
				errorString = e.getMessage();
			}
		}
		//set errorstring and employee then forward to views
		request.setAttribute("errorStrSSN", errorStrSSN);
		request.setAttribute("errorStrLastName", errorStrLastName);
		request.setAttribute("errorStrFirstName", errorStrFirstName);
		request.setAttribute("errorStrAddress", errorStrAddress);
		request.setAttribute("errorStrZipCode", errorStrZipCode);
		request.setAttribute("errorStrTelephone", errorStrTelephone);
		request.setAttribute("errorStrId", errorStrId);
		request.setAttribute("errorStrStartDate", errorStrStartDate);
		request.setAttribute("errorStrHourlyRate", errorStrHourlyRate);
		
		
		request.setAttribute("SSN", SSN);
		request.setAttribute("lastName", lastName);
		request.setAttribute("firstName", firstName);
		request.setAttribute("address", address);
		request.setAttribute("zipCode", zipCode);
		request.setAttribute("telephone", telephone);
		request.setAttribute("id", id);
		request.setAttribute("startDate", startDate);
		request.setAttribute("hourlyRate", hourlyRate);
		request.setAttribute("employee", employee);
		//If there's an error, stay on createEmployeeView
		if(hasError){
			RequestDispatcher dispatcher = request.getServletContext()
					.getRequestDispatcher("/WEB-INF/views/createEmployeeView.jsp");
			dispatcher.forward(request, response);
		}
		
		//If everything worked, redirect to the employeeList
		else{
			response.sendRedirect(request.getContextPath() + "/manager/employeeList");
		}
		
	}
	@Override
	protected void doPost(HttpServletRequest request, HttpServletResponse response)
	            throws ServletException, IOException {
	        doGet(request, response);
	    }
	
}