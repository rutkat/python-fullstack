import pandas as pd
import mplfinance as mpf
import yfinance as yf

ticker = yf.Ticker('AAPL')
data = ticker.history(period='1d', interval='1h')
# data = pd.read_csv('your_data.csv', index_col=0, parse_dates=True)

mpf.plot(data, type='candle', style='MSTR', volume=True)

mpf.plot(data, type='candle', volume=True, style='yahoo')

mpf.plot(data, type='candle', title='Customized Candlestick Chart',
          style='charles', volume=True,
          ylabel='Price', ylabel_lower='Volume')