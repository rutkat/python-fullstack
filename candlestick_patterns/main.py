from datetime import datetime
import matplotlib.pyplot as plt
import seaborn
import yfinance as yf

end_date = datetime(year=2025, month=8, day=1)
start_date = datetime(year=2025, month=1, day=1)

# set the name of the ticker we want to download market data for
ticker = "NVDA"

# download market data for a single ticker
df_single = yf.download(
    tickers=ticker,
    start=start_date,
    end=end_date,
    interval="1d",
    group_by="ticker",
    auto_adjust=True,
    progress=False
)

# print(df_single)
# print(df_single.columns)

# define the list of tickers we want to fetch market data for
tickers = ["NVDA", "META", "AAPL"]

# download market data for a multiple tickers
df_multi = yf.download(
    tickers=tickers,
    start=start_date,
    end=end_date,
    interval="1d",
    group_by="ticker",
    auto_adjust=True,
    progress=False
)
print(df_multi)
print(df_multi.columns)
print(df_multi["AAPL"]["Close"])


# initialize a new figure
plt.figure(figsize=(14, 7))
seaborn.set(style="whitegrid")

# loop over the tickers
for ticker in tickers:
    # plot the closing price for each
    seaborn.lineplot(
        data=df_multi[ticker]["Close"],
        label=ticker,
        linewidth=2
    )

# set the plot title
plt.title(
    f"Stock Closing Prices ("
    f"{start_date.strftime('%Y-%m-%d')} "
    f"to {end_date.strftime('%Y-%m-%d')})"
)

# set the plot labels
plt.xlabel("Date")
plt.ylabel("Closing Price ($)")

# finish constructing the plot
plt.tight_layout()
plt.show()


