
package utils;

import java.sql.Connection;
import java.sql.Date;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import beans.Employee;
import beans.Person;
import beans.Stock;
//Add employee information
public class ManagerUtils {

	
	public static List<Employee> getEmployeeList(Connection conn) throws SQLException{
		String sql = "select E.*,P.* from Employee E, Person P where P.SSN=E.SSN";
		
		PreparedStatement pstm = conn.prepareStatement(sql);
		
		ResultSet rs = pstm.executeQuery();
		List<Employee> list = new ArrayList<Employee>();
		while(rs.next()){
			int SSN = rs.getInt("SSN");
			String firstName = rs.getString("firstName");
			String lastName = rs.getString("lastName");
			int id = rs.getInt("id");
			Date startDate = rs.getDate("startDate");
			int hourlyRate = rs.getInt("hourlyRate");
			Employee employee = new Employee(rs.getInt("SSN"), rs.getString("lastName"), rs.getString("firstName"), rs.getString("address"), rs.getInt("zipCode"), rs.getString("telephone"),
					rs.getInt("id"), rs.getDate("startDate"), rs.getInt("hourlyRate"));
			list.add(employee);
		}
		return list;
	}
	
	public static void addEmployee(Connection conn, Employee employee) throws SQLException{
		String sql = "insert into Person(SSN, LastName, FirstName, Address, ZipCode,"
				+ " Telephone) values (?, ?, ?, ?, ?, ?)";
		PreparedStatement pstm = conn.prepareStatement(sql);
		
		pstm.setInt		(1, employee.getSSN());
		pstm.setString	(2, employee.getLastName());
		pstm.setString	(3, employee.getFirstName());
		pstm.setString	(4, employee.getAddress());
		pstm.setInt		(5, employee.getZipCode());
		pstm.setString	(6, employee.getTelephone());
		pstm.executeUpdate();
		
		sql = "insert into Employee(ID, SSN, StartDate, HourlyRate)"
			+ " values(?, ?, ?, ?)";
		
		pstm = conn.prepareStatement(sql);
		
		pstm.setInt		(1, employee.getId());
		pstm.setInt		(2, employee.getSSN());
		pstm.setDate	(3, employee.getStartDate());
		pstm.setFloat	(4, employee.getHourlyRate());
		pstm.executeUpdate();
	}

	public static Employee findEmployee(Connection conn, int id) throws SQLException {
		String sql = "select E.* from Employee E where E.id = ?";
		
		PreparedStatement pstm = conn.prepareStatement(sql);
		pstm.setInt(1, id);
		ResultSet rs = pstm.executeQuery();
		
		if(rs.next()){
			int eId = rs.getInt("id");
			int SSN = rs.getInt("SSN");
			Date startDate = rs.getDate("startDate");
			int hourlyRate = rs.getInt("hourlyRate");
		
			Person person = findPerson(conn, SSN);
			String lastName = person.getLastName();
			String firstName = person.getFirstName();
			String address = person.getAddress();
			int zipCode = person.getZipCode();
			String telephone = person.getTelephone();
			Employee employee = new Employee(SSN, lastName, firstName, address, 
				zipCode, telephone, eId, startDate, hourlyRate);
			return employee;
		}
		else
			return null;
	}

	public static Person findPerson(Connection conn, int PSSN) throws SQLException {
	String sql = "select P.* from Person P where P.SSN = ?";
		
		PreparedStatement pstm = conn.prepareStatement(sql);
		pstm.setInt(1, PSSN);
		ResultSet rs = pstm.executeQuery();
		
		if(rs.next()){
			int SSN = rs.getInt("SSN");
			String lastName = rs.getString("lastName");
			String firstName = rs.getString("firstName");
			String address = rs.getString("address");
			int zipCode = rs.getInt("zipCode");
			String telephone = rs.getString("telephone");
			Person person = new Person(SSN, lastName, firstName, address, 
				zipCode, telephone);
			return person;
		}
		else		
			return null;
	}

	public static void updateEmployee(Connection conn, Employee employee) throws SQLException{
		String sql = "update EmployeeInfo  set LastName=?, FirstName=?, Address=?, ZipCode=?,"
			+	"Telephone=? where Id=?";
		PreparedStatement pstm = conn.prepareStatement(sql);
		
		pstm.setString	(1, employee.getLastName());
		pstm.setString	(2, employee.getFirstName());
		pstm.setString	(3, employee.getAddress());
		pstm.setInt		(4, employee.getZipCode());
		pstm.setString	(5, employee.getTelephone());
		pstm.setInt		(6, employee.getId());
		pstm.executeUpdate();
		
		sql = "update EmployeeInfo set hourlyRate = ? where id = ?";
		pstm = conn.prepareStatement(sql);
		pstm.setInt(1, employee.getHourlyRate());
		pstm.setInt(2, employee.getId());
	}
	public static List<Stock> getStockList(Connection conn) throws SQLException{
			String sql = "select * from Stock";
			PreparedStatement pstm = conn.prepareStatement(sql);
			ResultSet rs = pstm.executeQuery();
			
			List<Stock> list = new ArrayList<Stock>();
			while(rs.next()){
				String stockSymbol = rs.getString("stockSymbol");
				String companyName = rs.getString("companyName");
				String type = rs.getString("type");
				float pricePerShare = rs.getFloat("pricePerShare");
				Stock stock = new Stock(stockSymbol, companyName, type, pricePerShare);
				list.add(stock);
				
			}
			return list;
	}
	// Set the share price of a stock
	// "update Stock set PricePerShare = ? where StockSymbol = ?";
	
	

	
	// Edit employee information
	// "create view EmployeeInfo(LastName, FirstName, Address, ZipCode, Telephone,"
	//	+ " HourlyRate) as (select P.LastName, P.FirstName, P.Address, P.ZipCode, P.Telephone,"
	//		+ " E.HourlyRate from Person P, Employee E where P.SSN = ? and P.SSN = E.SSN)"
	// update EmployeeInfo E set E.LastName=?, E.FirstName=?, E.Address=?, E.ZipCode,"
	//	+ " E.Telephone=?, E.HourlyRate=?;" 
	
	
	// Delete employee information
	// delete from Employee where SSN = ?
	// delete from Person where SSN = ?
	// (might not delete Person, will see)
	
	// Obtain a sales report for a particular month
	// "Select Trns.*, S.StockSymbol, S.CompanyName, S.Type, O.NumShares, O.Order, O.Price"
	//	+ " from 'Order' O, Stock S, Trade Trd, Transaction Trns"
	//		+ " where year(Trans.DateTime) = ? and month(Trns.DateTime) = ?"
	//			+ " and Trd.TransactionId = TrnsId and Trd.OrderId = O.Id and Trd.StockId = S.StockSymbol"
	//				+ "order by Trns.DateTime descs
	
	
	// Produce a comprehensive listing of all stocks
	
	// "select S.* from Stock S order by S.Type, S.StockSymbol;"
	
	//Produce a list of orders by stock symbol or by customer name
	//By stock symbol
	//"select distinct O.* from orders O, stock S, trade Trd where Trd.StockId = S.StockSymbol and O.Stock = ?"
	
	//by customer name
	//"select O.*, S.StockSymbol, S.CompanyName from Account A, Client C, Order O, Person P, Stock S, Trade Trd"
	//	+ " where P.LastName like ? and P.FirstName like ?"
	// 		+ " and C.Id = P.SSN and A.Client = C.Id and Trd.AccountId = A.Id and O.Id = Trd.OrderId and S.StockSymbol=Trd.StockId"
	
	
	// Produce a summary listing of revenue generated by a particular stock, stock type, or customer
	// By particular stock
	// "select S.StockSymbol, S.CompanyName, sum(Trns.Fee) as Revenue"
	//	+ " from Stock S, Trade Trd, Transaction Trns"
	//		+ " where S.StockSymbol = ? and Trd.StockId = S.StockSymbol and Trns.Id = Trd.TransactionId"
	//			+ " and trns.DateTime not null group by S.StockSymbol, S.CompanyName
	
	// by stock type
	// "select S.Type, sum(Trns.Fee) from Stock S, Trade Trd, Transaction Trns"
	//	+ " where S.Type = ? and Trd.StockId = S.StockSymbol and Trns.Id = Trd.TransactionId"
	//		+ " and trns.DateTime not null group by S.Type"
	
	// by a particular customer
	// select C.Id, P.LastName, P.FirstName, SUM(Trns.Free) from Trade Trd, Transaction Trns"
	// + " where C.Id = ? and P.SSN = C.Id and A.Clinet = C.Id and Trd.AccountId = A.Id"
	//	+ " and Trns.Id = Trd.TransactionId and Trns.DateTime not null"
	
	// Determine which customer representative generated most total revenue
	// "select P.LastName, P.FirstName, E.Id, sum(Trns.Fee) as Revenue" 
	// + " from Employee E, Person P, Trade Trd, Transaction Trns:
	//	+ " where E.SSN = P.SSN and Trd.BrokerId = E.Id and Trns.Id = Trd.TransactionId"
	//		+ " and Trns.DateTime not null group by E.Id order by desc Revenue limit 1"
	
	// Determine which customer generated most total revenue
	// "select P.LastName, P.FirstName, C.Id, sum(Trns.Fee) as Revenue"
	// + " Account A, Client C, Person P, Trade Trd, Transaction Trns"
	//	+ " where C.Id = P.SSN and A.Client = C.Id and Trd.AccountId = A.Id"
	//		+ " and Trns.Id = Trd.TransactionId and Trns.DateTime not null group by C.Id"
	//			+ " order by desc Revenue limit 1"
	
	// Produce a list of most actively traded stocks
	// "select count(*) as TimesTraded, S.StockSymbol, S.CompanyName"
	// + " from Stock S, Trade Trd, Transaction Trns"
	// 	+ " where S.StockSymbol = Trd.StockId and Trns.Id = Trd.TransactionId"
	// 		+ " and Trns.DateTime not null group by S.StockSymbol order by desc TimesTraded limit 20"
	
	
	public static Stock findStock(Connection conn, String stockSymbol) throws SQLException {
		String sql = "select * from Stock where stockSymbol = ?";
			
			PreparedStatement pstm = conn.prepareStatement(sql);
			pstm.setString(1, stockSymbol);
			ResultSet rs = pstm.executeQuery();
			
			if(rs.next()){
				String companyName = rs.getString("companyName");
				String type = rs.getString("type");
				float pricePerShare= rs.getFloat("pricePerShare");
				Stock stock = new Stock(stockSymbol, companyName, type, pricePerShare);
				return stock;
			}
			else		
				return null;
		}	
	public static void updateSharePrice(Connection conn, Stock stock) throws SQLException{
			String sql = "update Stock set pricePerShare = ? where stockSymbol = ?";
			PreparedStatement pstm = conn.prepareStatement(sql);
			
			pstm.setFloat	(1, stock.getPricePerShare());
			pstm.setString	(2, stock.getStockSymbol());
			pstm.executeUpdate();
		}
	
	public static void deleteEmployee(Connection conn, int id) throws SQLException {
		String sql = "select SSN from Employee where id = ?";
		PreparedStatement pstm = conn.prepareStatement(sql);
		pstm = conn.prepareStatement(sql);
		pstm.setInt(1, id);
		ResultSet rs = pstm.executeQuery();
		rs.next();
		int SSN = rs.getInt("SSN");
		
		sql = "delete from Employee where id = ?";
		pstm = conn.prepareStatement(sql);
		pstm.setInt(1, id);
		pstm.executeUpdate();
		
		
		sql = "delete from Person where SSN = ?";
		pstm = conn.prepareStatement(sql);
		pstm.setInt(1, SSN);
		pstm.executeUpdate();
	}
	
}

