Rails.application.routes.draw do
  root 'home#index'
  devise_for :users, :controllers => { omniauth_callbacks: 'omniauth_callbacks', registrations: 'registrations',  }
  get 'setup/index'
  get '/setup/open' => 'setup#open'
  post '/setup/generate' => 'setup#generate'
  get '/setup' => 'setup#index'
  # For details on the DSL available within this file, see https://guides.rubyonrails.org/routing.html
end
