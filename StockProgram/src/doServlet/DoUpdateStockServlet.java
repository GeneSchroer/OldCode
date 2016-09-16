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

import beans.Stock;
import utils.ManagerUtils;
import utils.MyUtils;

@WebServlet(urlPatterns={"/doUpdateStock"})
public class DoUpdateStockServlet extends HttpServlet{
	private static final long serialVersionUID = 1L;
	public DoUpdateStockServlet(){
		super();
	}
	@Override
	protected void doGet(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, IOException{
		Connection conn = MyUtils.getStoredConnection(request);
		String stockSymbol = request.getParameter("stockSymbol");
		String companyName = request.getParameter("companyName");
		String type = request.getParameter("type");
		Float pricePerShare=null;
		boolean hasError=false;
		String errorStrPricePerShare=null;
		
		Stock stock=null;
		String errorString=null;
		try{
			pricePerShare = Float.parseFloat(request.getParameter("pricePerShare"));
			if(pricePerShare<0){
				hasError=true;
				errorStrPricePerShare="Invalid Share Price!";
			}
		}catch(Exception  e){
			hasError = true;
			errorStrPricePerShare="Invalid Share Price!";
		}
		if(!hasError){
			stock = new Stock(stockSymbol, companyName, type, pricePerShare);
			
			try{
				ManagerUtils.updateSharePrice(conn, stock);
			}
			catch(SQLException e){
				e.printStackTrace();
				errorString = e.getMessage();
			}
		}
		
		request.setAttribute("errorStrPricePerShare", errorStrPricePerShare);
		if(hasError){
			RequestDispatcher dispatcher = request.getServletContext()
					.getRequestDispatcher("/WEB-INF/views/updateStockPriceView.jsp");
			dispatcher.forward(request, response);
		}
		else{
			response.sendRedirect(request.getContextPath() + "/stockList");
		}
	} 
	@Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        doGet(request, response);
    }
}
